//! DPoT Validator Directory module.

use alloy_primitives::Address;
use std::collections::HashMap;

/// Represents the type of a validator in the DPoT system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorType {
    /// Hardware TEE validator (high security).
    HardwareTEE,
    /// Vanilla Social validator (reputation based).
    VanillaSocial,
}

/// DPoT Validator Directory.
#[derive(Debug, Default)]
pub struct ValidatorRegistry {
    validators: HashMap<Address, ValidatorType>,
}

impl ValidatorRegistry {
    /// Creates a new, empty validator registry.
    pub fn new() -> Self {
        Self {
            validators: HashMap::new(),
        }
    }

    /// Registers a validator.
    pub fn register(&mut self, address: Address, vtype: ValidatorType) {
        self.validators.insert(address, vtype);
    }

    /// Unregisters a validator.
    pub fn unregister(&mut self, address: &Address) {
        self.validators.remove(address);
    }

    /// Checks if an address is registered and returns its type.
    pub fn get_type(&self, address: &Address) -> Option<ValidatorType> {
        self.validators.get(address).copied()
    }
}
