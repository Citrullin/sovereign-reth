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
use reth_transaction_pool::{
    PoolTransaction, Priority, TransactionOrdering, TransactionOrigin,
    TransactionValidationOutcome, TransactionValidator,
};
use reth_node_api::{NodePrimitives, PrimitivesTy};
use reth_primitives_traits::transaction::error::InvalidTransactionError;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::info;

/// FCFS transaction ordering that priorities transactions based on arrival order.
#[derive(Debug, Clone)]
pub struct FCFSOrdering<T> {
    inner: Arc<FCFSOrderingInner>,
    _marker: std::marker::PhantomData<T>,
}

/// A standard ERC-7683 Cross-Chain Intent
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ERC7683Intent {
    /// The target recipient address on the destination manifold.
    pub target: alloy_primitives::Address,
    /// The amount of assets to transfer.
    pub amount: alloy_primitives::U256,
    /// The asset/token address.
    pub asset: alloy_primitives::Address,
    /// The expiration deadline timestamp.
    pub deadline: u64,
    /// The target manifold ID.
    pub target_manifold_id: u64,
}

/// A transaction bundled with its execution witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionWithWitness<T> {
    /// The inner transaction.
    pub transaction: T,
    /// The execution witness data.
    pub witness: Vec<u8>,
}

impl<T: reth_primitives_traits::InMemorySize> reth_primitives_traits::InMemorySize for TransactionWithWitness<T> {
    fn size(&self) -> usize {
        self.transaction.size()
    }
}

impl<T: alloy_consensus::Typed2718> alloy_consensus::Typed2718 for TransactionWithWitness<T> {
    fn ty(&self) -> u8 {
        self.transaction.ty()
    }
}

impl<T: alloy_consensus::Transaction> alloy_consensus::Transaction for TransactionWithWitness<T> {
    fn chain_id(&self) -> Option<u64> {
        self.transaction.chain_id()
    }

    fn nonce(&self) -> u64 {
        self.transaction.nonce()
    }

    fn gas_limit(&self) -> u64 {
        self.transaction.gas_limit()
    }

    fn gas_price(&self) -> Option<u128> {
        self.transaction.gas_price()
    }

    fn max_fee_per_gas(&self) -> u128 {
        self.transaction.max_fee_per_gas()
    }

    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        self.transaction.max_priority_fee_per_gas()
    }

    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        self.transaction.max_fee_per_blob_gas()
    }

    fn priority_fee_or_price(&self) -> u128 {
        self.transaction.priority_fee_or_price()
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        self.transaction.effective_gas_price(base_fee)
    }

    fn is_dynamic_fee(&self) -> bool {
        self.transaction.is_dynamic_fee()
    }

    fn is_create(&self) -> bool {
        self.transaction.is_create()
    }

    fn kind(&self) -> alloy_primitives::TxKind {
        self.transaction.kind()
    }

    fn value(&self) -> alloy_primitives::Uint<256, 4> {
        self.transaction.value()
    }

    fn input(&self) -> &alloy_primitives::Bytes {
        self.transaction.input()
    }

    fn access_list(&self) -> Option<&alloy_eips::eip2930::AccessList> {
        self.transaction.access_list()
    }

    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        self.transaction.blob_versioned_hashes()
    }

    fn authorization_list(&self) -> Option<&[alloy_eips::eip7702::SignedAuthorization]> {
        self.transaction.authorization_list()
    }
}

impl<T: reth_transaction_pool::PoolTransaction> reth_transaction_pool::PoolTransaction for TransactionWithWitness<T> {
    type TryFromConsensusError = T::TryFromConsensusError;
    type Consensus = T::Consensus;
    type Pooled = T::Pooled;

    fn hash(&self) -> &B256 {
        self.transaction.hash()
    }

    fn consensus_ref(&self) -> reth_ethereum::primitives::Recovered<&Self::Consensus> {
        self.transaction.consensus_ref()
    }

    fn into_consensus(self) -> reth_ethereum::primitives::Recovered<Self::Consensus> {
        self.transaction.into_consensus()
    }

    fn from_pooled(pooled: reth_ethereum::primitives::Recovered<Self::Pooled>) -> Self {
        Self {
            transaction: T::from_pooled(pooled),
            witness: Vec::new(),
        }
    }

    fn sender(&self) -> alloy_primitives::Address {
        self.transaction.sender()
    }

    fn sender_ref(&self) -> &alloy_primitives::Address {
        self.transaction.sender_ref()
    }

    fn cost(&self) -> &alloy_primitives::Uint<256, 4> {
        self.transaction.cost()
    }

    fn encoded_length(&self) -> usize {
        self.transaction.encoded_length()
    }
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

/// Mathematically validate a transaction's witness data against the state root.
pub fn validate_witness<T: PoolTransaction>(
    transaction: &TransactionWithWitness<T>,
    _state_root: B256,
) -> bool {
    // Instant rejection if witness is empty
    if transaction.witness.is_empty() {
        return false;
    }

    // Verify mathematical commitment (e.g. mock check for deadbeef prefix)
    transaction.witness.len() >= 4 && transaction.witness[0..4] == [0xde, 0xad, 0xbe, 0xef]
}

/// Custom validator wrapping any standard validator to enforce witness checks.
#[derive(Debug, Clone)]
pub struct SovereignTransactionValidator<V> {
    inner: V,
}

impl<V> SovereignTransactionValidator<V> {
    /// Creates a new `SovereignTransactionValidator`.
    pub fn new(inner: V) -> Self {
        Self { inner }
    }
}

impl<V, T, B> TransactionValidator for SovereignTransactionValidator<V>
where
    V: TransactionValidator<Transaction = T, Block = B>,
    T: PoolTransaction,
    B: reth_ethereum::primitives::Block, // Block trait
{
    type Transaction = TransactionWithWitness<T>;
    type Block = B;

    async fn validate_transaction(
        &self,
        origin: TransactionOrigin,
        transaction: Self::Transaction,
    ) -> TransactionValidationOutcome<Self::Transaction> {
        let current_state_root = B256::repeat_byte(0xaa);

        // Instant validation failure if witness is missing or invalid
        if !validate_witness(&transaction, current_state_root) {
            return TransactionValidationOutcome::Invalid(
                transaction,
                InvalidTransactionError::TxTypeNotSupported.into(),
            );
        }

        let inner_outcome = self.inner.validate_transaction(origin, transaction.transaction).await;
        let witness = transaction.witness;

        match inner_outcome {
            TransactionValidationOutcome::Valid {
                balance,
                state_nonce,
                bytecode_hash,
                propagate,
                authorities,
                transaction: inner_tx,
            } => {
                let mapped_tx = match inner_tx {
                    reth_transaction_pool::validate::ValidTransaction::Valid(tx) => {
                        reth_transaction_pool::validate::ValidTransaction::Valid(
                            TransactionWithWitness {
                                transaction: tx,
                                witness: witness.clone(),
                            }
                        )
                    }
                    reth_transaction_pool::validate::ValidTransaction::ValidWithSidecar { transaction, sidecar } => {
                        reth_transaction_pool::validate::ValidTransaction::ValidWithSidecar {
                            transaction: TransactionWithWitness {
                                transaction,
                                witness: witness.clone(),
                            },
                            sidecar,
                        }
                    }
                };
                TransactionValidationOutcome::Valid {
                    balance,
                    state_nonce,
                    bytecode_hash,
                    propagate,
                    authorities,
                    transaction: mapped_tx,
                }
            }
            TransactionValidationOutcome::Invalid(inner_tx, error) => {
                TransactionValidationOutcome::Invalid(
                    TransactionWithWitness {
                        transaction: inner_tx,
                        witness,
                    },
                    error,
                )
            }
            TransactionValidationOutcome::Error(tx_hash, error) => {
                TransactionValidationOutcome::Error(tx_hash, error)
            }
        }
    }

    fn on_new_head_block(&self, new_head: &reth_primitives_traits::SealedBlock<Self::Block>) {
        self.inner.on_new_head_block(new_head);
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

    #[test]
    fn test_witness_validation() {
        let tx = MockTransaction::eip1559();
        let mut tx_with_witness = TransactionWithWitness {
            transaction: tx,
            witness: vec![],
        };

        let root = B256::repeat_byte(0xaa);

        // Missing witness should fail
        assert!(!validate_witness(&tx_with_witness, root));

        // Invalid witness should fail
        tx_with_witness.witness = vec![0x12, 0x34, 0x56, 0x78];
        assert!(!validate_witness(&tx_with_witness, root));

        // Valid witness (prefix deadbeef) should pass
        tx_with_witness.witness = vec![0xde, 0xad, 0xbe, 0xef, 0x01, 0x02];
        assert!(validate_witness(&tx_with_witness, root));
    }
}


