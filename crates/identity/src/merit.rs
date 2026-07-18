//! Interface for local TinyMeritRank.

use alloy_primitives::Address;

/// Interface for the TinyMeritRank reputation store.
pub trait MeritStore {
    /// Retrieves the merit rank of an address.
    fn get_rank(&self, address: &Address) -> Result<u64, String>;
    
    /// Updates the merit rank of an address.
    fn set_rank(&mut self, address: Address, new_rank: u64) -> Result<(), String>;
}
