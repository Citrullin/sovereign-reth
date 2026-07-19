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

    /// Checks for cartel formation (nodes giving >20% of their endorsement weight to mutual endorsers)
    pub fn slash_cartels(registry: &mut crate::registry::ValidatorRegistry, slash_amount: f64) {
        let mut to_slash = Vec::new();
        for (u, targets) in &registry.endorsements {
            let total_out: f64 = targets.values().sum();
            if total_out == 0.0 { continue; }
            
            let mut mutual_weight = 0.0;
            for (v, &weight) in targets {
                if let Some(v_targets) = registry.endorsements.get(v) {
                    if v_targets.contains_key(u) {
                        mutual_weight += weight;
                    }
                }
            }
            
            if mutual_weight / total_out > 0.20 {
                to_slash.push(u.clone());
            }
        }
        
        for did in to_slash {
            if let Some(rep) = registry.reputation.get_mut(&did) {
                *rep = (*rep - slash_amount).max(0.0);
            }
        }
    }

    /// Slashes nodes that failed to submit their KZG commitment within the epoch publishing window.
    pub fn slash_missing_commitments(registry: &mut crate::registry::ValidatorRegistry, slash_amount: f64) {
        let mut to_slash = Vec::new();
        for did in registry.reputation.keys() {
            if !registry.commitments.contains_key(did) {
                to_slash.push(did.clone());
            }
        }
        
        for did in to_slash {
            if let Some(rep) = registry.reputation.get_mut(&did) {
                *rep = (*rep - slash_amount).max(0.0);
            }
        }
        
        // Reset commitments for the next epoch
        registry.commitments.clear();
    }

