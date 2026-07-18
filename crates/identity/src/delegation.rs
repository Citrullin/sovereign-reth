//! Session key authorization checks.

use alloy_primitives::Address;

/// Represents a delegated session key.
#[derive(Debug, Clone)]
pub struct SessionKey {
    /// The address of the delegated key.
    pub key: Address,
    /// The timestamp when the session expires.
    pub expires_at: u64,
}

impl SessionKey {
    /// Checks if the session key is authorized at the given timestamp.
    /// Expiry is typically 24h.
    pub fn is_authorized(&self, current_timestamp: u64) -> bool {
        current_timestamp <= self.expires_at
    }
}
