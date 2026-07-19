//! Establish Overlapping Validator cross-manifold gossip queues for routing write intents.

use std::collections::VecDeque;

/// A cross-manifold gossip router.
pub struct BgpGossipRouter {
    /// Queues of write intents per manifold ID.
    pub write_intents: std::collections::HashMap<u64, VecDeque<Vec<u8>>>,
}

impl Default for BgpGossipRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl BgpGossipRouter {
    /// Creates a new BGP gossip router.
    #[must_use]
    pub fn new() -> Self {
        Self {
            write_intents: std::collections::HashMap::new(),
        }
    }

    /// Routes a write intent to an adjacent manifold.
    pub fn route_intent(&mut self, target_manifold: u64, intent: Vec<u8>) {
        self.write_intents
            .entry(target_manifold)
            .or_default()
            .push_back(intent);
    }

    /// Processes outgoing intents for a given manifold.
    pub fn process_outgoing(&mut self, target_manifold: u64) -> Option<Vec<u8>> {
        self.write_intents
            .get_mut(&target_manifold)
            .and_then(VecDeque::pop_front)
    }
}
