//! Identity & Reputation Module
//! Handles DID Peer 4 resolution and identity management.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]

pub mod delegation;
pub mod merit;
pub mod zkp_auth;

/// A simple struct representing a DID Peer 4 identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidPeer4 {
    /// The public key or multibase payload of the DID.
    pub payload: String,
}

impl DidPeer4 {
    /// Resolves a DID string statically.
    pub fn resolve(did: &str) -> Result<Self, &'static str> {
        if !did.starts_with("did:peer:4:") {
            return Err("Invalid DID format. Must start with 'did:peer:4:'");
        }
        
        // Statically slice out the payload part
        let payload = did.trim_start_matches("did:peer:4:").to_string();
        
        Ok(Self { payload })
    }
}
