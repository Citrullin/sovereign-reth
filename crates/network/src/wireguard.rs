//! Manage `wg0` interface and parse `did:peer:4` URIs.

/// WireGuard interface manager.
pub struct WireguardManager {
    /// Name of the interface (e.g., `wg0`).
    pub interface_name: String,
}

impl WireguardManager {
    /// Initializes a new WireguardManager.
    pub fn new(interface_name: &str) -> Self {
        Self {
            interface_name: interface_name.to_string(),
        }
    }

    /// Sets up the interface.
    pub fn setup_interface(&self, _private_key: &str, _listen_port: u16) -> Result<(), String> {
        // In a real implementation we would use netlink or `wg` CLI.
        // E.g., `ip link add dev wg0 type wireguard`
        // `wg set wg0 private-key /tmp/privkey listen-port 51820`
        // `ip link set up dev wg0`
        Ok(())
    }

    /// Adds a peer by parsing its `did:peer:4` URI.
    pub fn add_peer_from_did(&self, did: &str, _endpoint_ip: &str) -> Result<(), String> {
        if !did.starts_with("did:peer:4:") {
            return Err("Invalid DID format".into());
        }
        
        // Extract public key and setup peer.
        // wg set wg0 peer <PUBKEY> allowed-ips <IP>/32 endpoint <ENDPOINT>
        // Here we would also trigger validator registry whitelisting upon success.
        
        Ok(())
    }
}
