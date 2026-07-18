//! Custom transaction pool construction and First-Come-First-Serve (FCFS) transaction ordering.

use alloy_primitives::B256;
use reth_chainspec::EthereumHardforks;
use reth_ethereum::{
    evm::primitives::ConfigureEvm,
    node::{
        api::{FullNodeTypes, NodeTypes},
        builder::{components::PoolBuilder, BuilderContext},
    },
    pool::{blobstore::InMemoryBlobStore, Pool, PoolConfig, TransactionValidationTaskExecutor},
    provider::CanonStateSubscriptions,
};
use reth_node_api::{NodePrimitives, PrimitivesTy};
use reth_transaction_pool::{PoolTransaction, Priority, TransactionOrdering};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::info;

/// FCFS transaction ordering that priorities transactions based on arrival order.
#[derive(Debug, Clone)]
pub struct FCFSOrdering<T> {
    inner: Arc<FCFSOrderingInner>,
    _marker: std::marker::PhantomData<T>,
}

#[derive(Debug)]
struct FCFSOrderingInner {
    next_sequence: Mutex<u64>,
    sequences: Mutex<HashMap<B256, u64>>,
}

impl<T> FCFSOrdering<T> {
    /// Creates a new `FCFSOrdering`.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(FCFSOrderingInner {
                next_sequence: Mutex::new(0),
                sequences: Mutex::new(HashMap::new()),
            }),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<T> Default for FCFSOrdering<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: PoolTransaction> TransactionOrdering for FCFSOrdering<T> {
    type PriorityValue = u64;
    type Transaction = T;

    fn priority(
        &self,
        transaction: &Self::Transaction,
        _base_fee: u64,
    ) -> Priority<Self::PriorityValue> {
        let hash = *transaction.hash();
        let mut sequences = self.inner.sequences.lock().unwrap();
        let seq = if let Some(&seq) = sequences.get(&hash) {
            seq
        } else {
            let mut next = self.inner.next_sequence.lock().unwrap();
            let seq = *next;
            *next += 1;
            sequences.insert(hash, seq);
            seq
        };
        Priority::Value(u64::MAX - seq)
    }
}

/// Custom Pool Builder that sets up the FCFS transaction pool.
#[derive(Debug, Clone, Default)]
pub struct SovereignPoolBuilder {
    pool_config: PoolConfig,
}

impl SovereignPoolBuilder {
    /// Creates a new `SovereignPoolBuilder` with default configuration.
    pub fn new(pool_config: PoolConfig) -> Self {
        Self { pool_config }
    }
}

impl<Types, N, Evm> PoolBuilder<N, Evm> for SovereignPoolBuilder
where
    Types: NodeTypes<
        ChainSpec: EthereumHardforks,
        Primitives: NodePrimitives<SignedTx = reth_ethereum_primitives::TransactionSigned>,
    >,
    N: FullNodeTypes<Types = Types>,
    Evm: ConfigureEvm<Primitives = PrimitivesTy<Types>> + Clone + 'static,
{
    type Pool = Pool<
        TransactionValidationTaskExecutor<
            reth_ethereum::pool::EthTransactionValidator<
                N::Provider,
                reth_ethereum::pool::EthPooledTransaction,
                Evm,
            >,
        >,
        FCFSOrdering<reth_ethereum::pool::EthPooledTransaction>,
        InMemoryBlobStore,
    >;

    async fn build_pool(
        self,
        ctx: &BuilderContext<N>,
        evm_config: Evm,
    ) -> eyre::Result<Self::Pool> {
        let data_dir = ctx.config().datadir();
        let blob_store = InMemoryBlobStore::default();

        let validator =
            TransactionValidationTaskExecutor::eth_builder(ctx.provider().clone(), evm_config)
                .kzg_settings(ctx.kzg_settings()?)
                .with_additional_tasks(ctx.config().txpool.additional_validation_tasks)
                .build_with_tasks(ctx.task_executor().clone(), blob_store.clone());

        let transaction_pool =
            Pool::new(validator, FCFSOrdering::new(), blob_store, self.pool_config);
        info!(target: "reth::cli", "Sovereign FCFS Transaction pool initialized");

        let transactions_path = data_dir.txpool_transactions();
        {
            let pool = transaction_pool.clone();
            let chain_events = ctx.provider().canonical_state_stream();
            let client = ctx.provider().clone();
            let transactions_backup_config =
                reth_ethereum::pool::maintain::LocalTransactionBackupConfig::with_local_txs_backup(
                    transactions_path,
                );

            ctx.task_executor()
                .spawn_critical_with_graceful_shutdown_signal(
                    "local transactions backup task",
                    |shutdown| {
                        reth_ethereum::pool::maintain::backup_local_transactions_task(
                            shutdown,
                            pool.clone(),
                            transactions_backup_config,
                        )
                    },
                );

            ctx.task_executor().spawn_critical_task(
                "txpool maintenance task",
                reth_ethereum::pool::maintain::maintain_transaction_pool_future(
                    client,
                    pool,
                    chain_events,
                    ctx.task_executor().clone(),
                    reth_ethereum::pool::maintain::MaintainPoolConfig {
                        max_tx_lifetime: transaction_pool.config().max_queued_lifetime,
                        ..Default::default()
                    },
                ),
            );
        }
        Ok(transaction_pool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reth_transaction_pool::test_utils::MockTransaction;

    #[test]
    fn test_fcfs_ordering_priority() {
        let ordering = FCFSOrdering::new();
        
        let tx1 = MockTransaction::eip1559();
        let tx2 = MockTransaction::eip1559();
        
        let p1 = ordering.priority(&tx1, 0);
        let p2 = ordering.priority(&tx2, 0);
        
        // tx1 arrived first, so it should have a higher priority (lower sequence number)
        assert!(p1 > p2);
        
        // Querying tx1 again should return the same priority
        let p1_again = ordering.priority(&tx1, 0);
        assert_eq!(p1, p1_again);
    }
}


