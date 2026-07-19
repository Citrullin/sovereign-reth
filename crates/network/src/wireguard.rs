//! Manage `wg0` interface and parse `did:peer:4` URIs.

use std::process::Command;

/// `WireGuard` interface manager.
pub struct WireguardManager {
    /// Name of the interface (e.g., `wg0`).
    pub interface_name: String,
}

impl WireguardManager {
    /// Initializes a new `WireguardManager`.
    #[must_use]
    pub fn new(interface_name: &str) -> Self {
        Self {
            interface_name: interface_name.to_string(),
        }
    }

    /// Sets up the interface.
    ///
    /// # Errors
    /// Returns an error if the setup fails.
    pub fn setup_interface(&self, private_key: &str, listen_port: u16) -> Result<(), String> {
        if cfg!(debug_assertions) || std::env::var("SOVEREIGN_MOCK_WIREGUARD").is_ok() {
            // Dev/test fallback
            tracing::info!(
                interface = %self.interface_name,
                private_key = "[REDACTED]",
                listen_port,
                "WireGuard interface setup (Mock Mode)"
            );
            return Ok(());
        }

        // Write private key to a temporary file for safety
        let key_file = "/tmp/wg_private.key";
        std::fs::write(key_file, private_key)
            .map_err(|e| format!("Failed to write private key to file: {e}"))?;

        // 1. Create interface
        let status = Command::new("ip")
            .args(["link", "add", "dev", &self.interface_name, "type", "wireguard"])
            .status()
            .map_err(|e| format!("Failed to execute 'ip link add': {e}"))?;
        if !status.success() {
            return Err("Failed to create WireGuard interface (ip link add)".to_string());
        }

        // 2. Set private key and port
        let status = Command::new("wg")
            .args(["set", &self.interface_name, "private-key", key_file, "listen-port", &listen_port.to_string()])
            .status()
            .map_err(|e| format!("Failed to execute 'wg set': {e}"))?;
        
        let _ = std::fs::remove_file(key_file); // Clean up private key file
        
        if !status.success() {
            return Err("Failed to configure WireGuard keys (wg set)".to_string());
        }

        // 3. Bring interface UP
        let status = Command::new("ip")
            .args(["link", "set", "up", "dev", &self.interface_name])
            .status()
            .map_err(|e| format!("Failed to execute 'ip link set up': {e}"))?;
        if !status.success() {
            return Err("Failed to bring WireGuard interface up (ip link set up)".to_string());
        }

        Ok(())
    }

    /// Adds a peer by parsing its `did:peer:4` URI.
    ///
    /// # Errors
    /// Returns an error if the DID format is invalid.
    pub fn add_peer_from_did(&self, did: &str, endpoint_ip: &str) -> Result<(), String> {
        if !did.starts_with("did:peer:") {
            return Err("Invalid DID format".into());
        }

        // Extract key from DID.
        // A did:peer:4:z6M... contains a multibase-encoded public key.
        // We block on the async resolve method since it does not perform network IO.
        let resolved = futures::executor::block_on(sovereign_identity::DidPeer4::resolve(did))
            .map_err(|e| format!("Failed to resolve peer DID: {e}"))?;

        // Format public key to base64 (which WireGuard CLI expects)
        let public_key_b64 = ndarray_or_base64_format(&resolved.public_key);

        if cfg!(debug_assertions) || std::env::var("SOVEREIGN_MOCK_WIREGUARD").is_ok() {
            tracing::info!(
                interface = %self.interface_name,
                peer_did = %did,
                peer_pubkey = %public_key_b64,
                endpoint = %endpoint_ip,
                "WireGuard peer added (Mock Mode)"
            );
            return Ok(());
        }

        // wg set wg0 peer <PUBKEY> allowed-ips 10.0.0.x/32 endpoint <ENDPOINT>
        let status = Command::new("wg")
            .args([
                "set",
                &self.interface_name,
                "peer",
                &public_key_b64,
                "allowed-ips",
                &format!("{endpoint_ip}/32"),
                "endpoint",
                endpoint_ip,
            ])
            .status()
            .map_err(|e| format!("Failed to execute 'wg set peer': {e}"))?;

        if !status.success() {
            return Err("Failed to add peer to WireGuard interface (wg set peer)".to_string());
        }

        Ok(())
    }
}

// Simple base64 encoder helper since WireGuard expects standard base64 keys
fn ndarray_or_base64_format(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
