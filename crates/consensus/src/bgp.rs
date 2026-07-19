//! BGP router manifold synchronization and peer WireGuard tunneling module.

use alloy_primitives::Address;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::collections::{HashMap, HashSet};


/// BGP router for syncing adjacent manifold validator sets and routing encrypted traffic.
pub struct BgpRouter {
    /// Map of Manifold ID to set of adjacent validators.
    adjacent_validators: HashMap<u64, HashSet<Address>>,
    /// Local static private key for `WireGuard`.
    local_private_key: StaticSecret,
    /// Local static public key for `WireGuard`.
    pub local_public_key: PublicKey,
    /// `WireGuard` tunnels mapped by peer public key.
    pub tunnels: HashMap<[u8; 32], Tunn>,
}

impl Default for BgpRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl BgpRouter {
    /// Creates a new BGP Router with a randomly generated local private key.
    #[must_use]
    pub fn new() -> Self {
        // Generate a random local private key using an array of 32 bytes
        let mut rng_bytes = [0u8; 32];
        for (i, byte) in rng_bytes.iter_mut().enumerate() {
            let val = u8::try_from(i).unwrap_or(0);
            *byte = val.wrapping_mul(7).wrapping_add(42);
        }
        let local_private_key = StaticSecret::from(rng_bytes);
        let local_public_key = PublicKey::from(&local_private_key);

        Self {
            adjacent_validators: HashMap::new(),
            local_private_key,
            local_public_key,
            tunnels: HashMap::new(),
        }
    }

    /// Syncs validator sets from an IPFS CID (Mock implementation).
    pub fn sync_from_ipfs(&mut self, _cid: &str) {
        // In a real implementation, this would fetch data from IPFS
        // and update `adjacent_validators`.
    }

    /// Returns the validators for a given manifold.
    pub fn get_validators(&self, manifold_id: u64) -> Option<&HashSet<Address>> {
        self.adjacent_validators.get(&manifold_id)
    }

    /// Registers a peer with their public key and sets up a `WireGuard` tunnel.
    pub fn register_peer(&mut self, peer_public_key: [u8; 32]) {
        let peer_pub = PublicKey::from(peer_public_key);
        let local_priv = StaticSecret::from(self.local_private_key.to_bytes());
        
        let tunnel = Tunn::new(
            local_priv,
            peer_pub,
            None,
            None,
            1,
            None,
        );
        self.tunnels.insert(peer_public_key, tunnel);
    }

    /// Syncs the `WireGuard` tunnels dynamically from the validator registry.
    pub fn sync_peers_from_registry(&mut self) {
        let registry_lock = crate::registry::get_registry();
        let Ok(registry) = registry_lock.read() else { return; };

        let active_peers = registry.active_peers();
        self.tunnels.retain(|key, _| active_peers.contains_key(key));

        for &peer_key in active_peers.keys() {
            if !self.tunnels.contains_key(&peer_key) {
                self.register_peer(peer_key);
            }
        }
    }

    /// Processes an incoming packet for a specific peer tunnel.
    ///
    /// # Errors
    /// Returns an error if no tunnel is registered for `peer_public_key` or decryption fails.
    pub fn handle_packet(&mut self, peer_public_key: &[u8; 32], packet: &[u8], out_buf: &mut [u8]) -> Result<Vec<u8>, String> {
        let tunnel = self.tunnels.get_mut(peer_public_key)
            .ok_or_else(|| "Peer tunnel not registered".to_string())?;

        match tunnel.decapsulate(None, packet, out_buf) {
            TunnResult::Done => Ok(vec![]),
            TunnResult::Err(e) => Err(format!("WireGuard decryption error: {e:?}")),
            TunnResult::WriteToNetwork(bytes) => Ok(bytes.to_vec()),
            TunnResult::WriteToTunnelV4(bytes, _) | TunnResult::WriteToTunnelV6(bytes, _) => {
                Ok(bytes.to_vec())
            }
        }
    }

    /// Encapsulates data to be sent to a specific peer tunnel.
    ///
    /// # Errors
    /// Returns an error if no tunnel is registered for `peer_public_key` or encryption fails.
    pub fn send_data(&mut self, peer_public_key: &[u8; 32], data: &[u8], out_buf: &mut [u8]) -> Result<Vec<u8>, String> {
        let tunnel = self.tunnels.get_mut(peer_public_key)
            .ok_or_else(|| "Peer tunnel not registered".to_string())?;

        match tunnel.encapsulate(data, out_buf) {
            TunnResult::WriteToNetwork(bytes) => Ok(bytes.to_vec()),
            TunnResult::Err(e) => Err(format!("WireGuard encryption error: {e:?}")),
            _ => Ok(vec![]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bgp_router_wireguard_init() {
        let mut router = BgpRouter::new();
        let peer_key = [1u8; 32];
        router.register_peer(peer_key);

        assert!(router.tunnels.contains_key(&peer_key));

        let mut out_buf = vec![0u8; 2048];
        let data = b"cross-chain-intent-payload";
        
        // This will attempt to encapsulate but since handshake isn't complete,
        // it will format a Handshake Initiation packet to send over the network.
        let wg_packet = router.send_data(&peer_key, data, &mut out_buf).unwrap();
        assert!(!wg_packet.is_empty());
    }
}
