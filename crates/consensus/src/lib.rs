//! Sovereign Consensus Crate
//! Contains custom transaction ordering and pool builders.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::module_name_repetitions)]

pub mod pool;
pub mod stateless;
pub mod nmt;
pub mod registry;
pub mod bgp;
/// Cross-manifold precompiles module.
pub mod precompile;
pub mod slashing;
pub mod parallel;
pub mod subset_election;
pub mod courier;
pub mod kzg;
pub mod metalex;

pub use pool::{FCFSOrdering, SovereignPoolBuilder};
