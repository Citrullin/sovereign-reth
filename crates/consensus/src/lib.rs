//! Sovereign Consensus Crate
//! Contains custom transaction ordering and pool builders.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::module_name_repetitions)]

/// Custom FCFS transaction ordering and pool builders.
pub mod pool;
/// Sovereign configurations.
pub mod config;
/// Stateless EVM execution/validation.
pub mod stateless;
/// Namespaced Merkle Trees for state-diff partitioning.
pub mod nmt;
/// Validator registry and reputation.
pub mod registry;
/// BGP router sync and WireGuard peering.
pub mod bgp;
/// Cross-manifold precompiles module.
pub mod precompile;
/// Reputation slashing and decay rules.
pub mod slashing;
/// Parallel execution stubs.
pub mod parallel;
/// Snow-based subset election.
pub mod subset_election;
/// Paymaster and courier services.
pub mod courier;
/// `PageRank` KZG commitments.
pub mod kzg;
/// MetaLex organization management.
pub mod metalex;

pub use pool::{FCFSOrdering, SovereignPoolBuilder};
