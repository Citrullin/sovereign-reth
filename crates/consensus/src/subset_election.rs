//! Snow-based subset election module for cross-manifold relaying.
//!
//! Randomly samples validators from the routing pool every 15 minutes.

use alloy_primitives::Address;
use std::collections::HashSet;
use alloy_primitives::keccak256;

/// Represents a Snow subset election state.
pub struct SnowSubsetElection {
    /// The currently elected subset of validators.
    pub current_subset: HashSet<Address>,
    /// The manifold ID targeted by this election.
    pub manifold_id: u64,
}

impl SnowSubsetElection {
    /// Creates a new `SnowSubsetElection` helper.
    #[must_use]
    pub fn new(manifold_id: u64) -> Self {
        Self {
            current_subset: HashSet::new(),
            manifold_id,
        }
    }

    /// Triggers an election based on the given pool of routable validators.
    /// Uses a VRF-style deterministic sort based on epoch to sample the subset.
    ///
    /// # Errors
    /// Returns an error if the pool of routable validators is empty.
    pub fn trigger_election(&mut self, routable_validators: &HashSet<Address>, epoch: u64, subset_size: usize) -> Result<(), &'static str> {
        if routable_validators.is_empty() {
            self.current_subset.clear();
            return Err("No routable validators available for election.");
        }

        let mut payload = Vec::new();
        payload.extend_from_slice(&self.manifold_id.to_be_bytes());
        payload.extend_from_slice(&epoch.to_be_bytes());
        let seed = keccak256(&payload);

        let mut validators_vec: Vec<Address> = routable_validators.iter().copied().collect();
        
        // Sort deterministically based on distance to the seed hash
        validators_vec.sort_by_key(|addr| {
            let mut addr_payload = Vec::new();
            addr_payload.extend_from_slice(addr.as_slice());
            addr_payload.extend_from_slice(seed.as_slice());
            keccak256(&addr_payload)
        });
        
        let sample_size = std::cmp::min(validators_vec.len(), subset_size);
        self.current_subset = validators_vec.into_iter().take(sample_size).collect();
        
        Ok(())
    }
}
