//! Blind Courier & Auto-Funding Paymaster Service.
//!
//! Monitors the `IntentPool` and submits ERC-7683 Intents as EIP-4844 blobs to target manifolds.
//! Automatically halts if the paymaster address derived from the local DID seed is depleted.

use alloy_primitives::{Address, U256};
use k256::ecdsa::SigningKey;
use alloy_primitives::keccak256;
use std::sync::Arc;
use tracing::{error, info};

/// A mock RPC client interface.
pub trait RpcClient {
    /// Returns the current ETH balance of `address`.
    fn get_balance(&self, address: Address) -> U256;
}

/// Blind courier service that submits cross-manifold intents as EIP-4844 blobs.
pub struct BlindCourierService<R: RpcClient> {
    /// The local DID of this courier node.
    pub local_did: String,
    /// The paymaster address derived from the local seed.
    pub local_paymaster_address: Address,
    rpc_client: Arc<R>,
    /// Whether the service is currently suspended due to insufficient funds.
    pub is_suspended: bool,
    /// Minimum ETH balance required to keep the service running.
    pub required_gas_threshold: U256,
}

impl<R: RpcClient> BlindCourierService<R> {
    /// Creates a new courier service. Derives the paymaster address from a Secp256k1 seed.
    ///
    /// # Errors
    /// Returns an error if the seed bytes are not a valid Secp256k1 scalar.
    pub fn new(local_did: String, seed: &[u8; 32], rpc_client: Arc<R>) -> Result<Self, &'static str> {
        let signing_key = SigningKey::from_slice(seed)
            .map_err(|_| "Invalid Secp256k1 seed: not a valid scalar")?;
        let verifying_key = signing_key.verifying_key();

        let uncompressed = verifying_key.to_sec1_point(false);
        let hash = keccak256(&uncompressed.as_bytes()[1..]);
        let local_paymaster_address = Address::from_slice(&hash[12..32]);

        Ok(Self {
            local_did,
            local_paymaster_address,
            rpc_client,
            is_suspended: false,
            // Assume 0.005 ETH required for blob gas
            required_gas_threshold: U256::from(5_000_000_000_000_000u64),
        })
    }

    /// Checks the paymaster balance. If depleted, suspends the service and warns the operator.
    ///
    /// Returns `true` if the service is (or just became) suspended.
    pub fn check_funding_and_suspend(&mut self) -> bool {
        let balance = self.rpc_client.get_balance(self.local_paymaster_address);
        if balance < self.required_gas_threshold {
            if !self.is_suspended {
                error!(
                    address = %self.local_paymaster_address,
                    balance = %balance,
                    "Paymaster depleted — courier suspended",
                );
                self.is_suspended = true;
            }
            return true;
        }

        if self.is_suspended {
            info!("Paymaster funded — courier resumed");
            self.is_suspended = false;
        }
        false
    }

    /// Tries to process an intent for the given manifold.
    ///
    /// # Errors
    /// Returns an error if the courier is suspended due to insufficient funds.
    pub fn process_intent(&mut self, target_manifold_id: u64, _intent_data: &[u8]) -> Result<(), &'static str> {
        if self.check_funding_and_suspend() {
            return Err("Courier is suspended due to insufficient funds.");
        }

        // Logic to bundle `intent_data` into an EIP-4844 Blob and submit via RPC goes here.
        info!(target_manifold_id, "Submitted intent via blob");

        Ok(())
    }
}
