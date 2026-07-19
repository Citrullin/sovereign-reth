//! Interface for local `TinyMeritRank`.
//!
//! This is a placeholder trait for the reputation store.
//! TODO: Implement with the validator registry once the store format is stable.

use alloy_primitives::Address;

/// Interface for the `TinyMeritRank` reputation store.
///
/// Not yet implemented — see [`crate::registry::ValidatorRegistry`] for the
/// current in-memory PageRank-based reputation system.
pub trait MeritStore {
    /// Retrieves the merit rank of an address.
    ///
    /// # Errors
    /// Returns an error string if the address is unknown.
    fn get_rank(&self, address: &Address) -> Result<u64, String>;

    /// Updates the merit rank of an address.
    ///
    /// # Errors
    /// Returns an error string if the update fails.
    fn set_rank(&mut self, address: Address, new_rank: u64) -> Result<(), String>;
}
