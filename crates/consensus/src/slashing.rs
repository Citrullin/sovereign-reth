//! Reputation slashing and decay rules module.

use alloy_primitives::Address;
use std::collections::HashMap;

/// ReputationSlash handler and TinyMeritRank rules.
#[derive(Debug, Default)]
pub struct SlashingManager {
    /// Current merit rank of validators.
    merit_rank: HashMap<Address, u64>,
}

impl SlashingManager {
    /// Creates a new SlashingManager.
    pub fn new() -> Self {
        Self {
            merit_rank: HashMap::new(),
        }
    }

    /// Handles a reputation slash.
    pub fn slash(&mut self, address: Address, amount: u64) {
        if let Some(rank) = self.merit_rank.get_mut(&address) {
            *rank = rank.saturating_sub(amount);
            // $O(1)$ auto-eviction handled by checking threshold during selection
        }
    }

    /// Applies TinyMeritRank decay rules over an epoch.
    pub fn decay(&mut self, decay_factor: u64) {
        for rank in self.merit_rank.values_mut() {
            *rank = rank.saturating_sub(decay_factor);
        }
    }

    /// Checks if a validator is still in the allowed sequencers set based on threshold.
    pub fn is_allowed_sequencer(&self, address: &Address, threshold: u64) -> bool {
        self.merit_rank.get(address).copied().unwrap_or(0) >= threshold
    }
}
