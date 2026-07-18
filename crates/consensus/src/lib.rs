//! Sovereign Consensus Crate
//! Contains custom transaction ordering and pool builders.

#![warn(missing_docs)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::module_name_repetitions)]

pub mod pool;

pub use pool::{FCFSOrdering, SovereignPoolBuilder};
