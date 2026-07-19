use alloy_primitives::keccak256;
use boringtun::x25519::{StaticSecret, PublicKey};

/// Derives multiple key types from a single master seed.
pub struct KeyDeriver {
    /// The master seed.
    pub master_seed: [u8; 32],
}

impl Drop for KeyDeriver {
    fn drop(&mut self) {
        self.master_seed.fill(0);
    }
}

impl KeyDeriver {
    /// Creates a new key deriver from a 32-byte seed.
    pub fn new(master_seed: [u8; 32]) -> Self {
        Self { master_seed }
    }

    /// Derives a Curve25519 keypair for WireGuard.
    pub fn derive_curve25519(&self) -> ([u8; 32], [u8; 32]) {
        let mut seed = [0u8; 42];
        seed[..10].copy_from_slice(b"curve25519");
        seed[10..].copy_from_slice(&self.master_seed);
        let priv_bytes = keccak256(&seed).0;
        let local_priv = StaticSecret::from(priv_bytes);
        let local_pub = PublicKey::from(&local_priv);
        let pub_bytes = *local_pub.as_bytes();
        (priv_bytes, pub_bytes)
    }

    /// Derives an Ed25519 keypair for standard signing.
    pub fn derive_ed25519(&self) -> ([u8; 32], [u8; 32]) {
        let mut seed = [0u8; 39];
        seed[..7].copy_from_slice(b"ed25519");
        seed[7..].copy_from_slice(&self.master_seed);
        let priv_bytes = keccak256(&seed).0;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&priv_bytes);
        let verifying_key = signing_key.verifying_key();
        (priv_bytes, verifying_key.to_bytes())
    }

    /// Derives a secp256k1 keypair for EVM compat.
    pub fn derive_secp256k1(&self) -> ([u8; 32], [u8; 33]) {
        let mut seed = [0u8; 41];
        seed[..9].copy_from_slice(b"secp256k1");
        seed[9..].copy_from_slice(&self.master_seed);
        let mut priv_bytes = keccak256(&seed).0;
        
        let signing_key = loop {
            if let Ok(key) = k256::ecdsa::SigningKey::from_bytes(&priv_bytes.into()) {
                break key;
            }
            priv_bytes = keccak256(&priv_bytes).0;
        };

        let verifying_key = signing_key.verifying_key();
        let pub_point = verifying_key.to_sec1_point(true); // compressed
        let mut out_pub = [0u8; 33];
        out_pub.copy_from_slice(pub_point.as_bytes());
        (priv_bytes, out_pub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation() {
        let master_seed = [42u8; 32];
        let deriver = KeyDeriver::new(master_seed);
        
        let (wg_priv, wg_pub) = deriver.derive_curve25519();
        assert_ne!(wg_priv, [0u8; 32]);
        assert_ne!(wg_pub, [0u8; 32]);
        
        let (ed_priv, ed_pub) = deriver.derive_ed25519();
        assert_ne!(ed_priv, [0u8; 32]);
        assert_ne!(ed_pub, [0u8; 32]);
        
        let (secp_priv, secp_pub) = deriver.derive_secp256k1();
        assert_ne!(secp_priv, [0u8; 32]);
        assert_ne!(secp_pub, [0u8; 33]);

        // Verify determinism
        let deriver2 = KeyDeriver::new(master_seed);
        assert_eq!(deriver2.derive_curve25519(), (wg_priv, wg_pub));
        assert_eq!(deriver2.derive_ed25519(), (ed_priv, ed_pub));
        assert_eq!(deriver2.derive_secp256k1(), (secp_priv, secp_pub));
    }
}
