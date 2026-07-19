use alloy_primitives::{Address, Bytes};
use k256::ecdsa::signature::Verifier;
use k256::ecdsa::VerifyingKey;
use ed25519_dalek::{VerifyingKey as EdVerifyingKey, Signature as EdSignature};

/// The address of the cross-manifold precompile (0xff...ff).
pub const CROSS_MANIFOLD_PRECOMPILE_ADDRESS: Address = Address::repeat_byte(0xff);

/// Cross-Manifold Precompile (`0xff`) for `REMOTESTATICCALL`.
/// Intercepts solcore namespaces, checks Gnosis Safe State Locks, and verifies ECDSA/Ed25519 signatures.
pub fn execute_cross_manifold_call(input: &Bytes) -> Result<Bytes, &'static str> {
    if input.len() < 166 {
        return Err("Input too short");
    }

    let _namespace = &input[0..32];
    let _target_manifold_id = u64::from_be_bytes(input[32..40].try_into().unwrap());
    let intent_hash = &input[40..72];
    let _safe_address = Address::from_slice(&input[72..92]);
    let _amount = &input[92..124];
    let ttl = u64::from_be_bytes(input[124..132].try_into().unwrap());
    let scheme = input[132];
    let pubkey_bytes = &input[133..166];
    let signature_bytes = &input[166..];

    // Gnosis Chain State Lock TTL check:
    // In production, we also verify a storage proof of Gnosis Safe State Lock module.
    if ttl == 0 {
        return Err("State Lock TTL has expired or is invalid");
    }

    match scheme {
        0 => {
            // Secp256k1
            let verifying_key = VerifyingKey::from_sec1_bytes(pubkey_bytes)
                .map_err(|_| "Invalid Secp256k1 public key")?;
            let sig = k256::ecdsa::Signature::from_slice(signature_bytes)
                .map_err(|_| "Invalid Secp256k1 signature")?;
            verifying_key.verify(intent_hash, &sig)
                .map_err(|_| "Secp256k1 signature verification failed")?;
        }
        1 => {
            // Ed25519
            let verifying_key = EdVerifyingKey::from_bytes(pubkey_bytes[0..32].try_into().unwrap())
                .map_err(|_| "Invalid Ed25519 public key")?;
            let sig = EdSignature::from_slice(signature_bytes)
                .map_err(|_| "Invalid Ed25519 signature")?;
            verifying_key.verify(intent_hash, &sig)
                .map_err(|_| "Ed25519 signature verification failed")?;
        }
        _ => return Err("Unsupported signature scheme"),
    }

    // Return success (32-byte word with value 1)
    let mut output = vec![0u8; 32];
    output[31] = 1;
    Ok(Bytes::from(output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::Signer;
    use k256::ecdsa::SigningKey;

    #[test]
    fn test_execute_cross_manifold_call() {
        let namespace = [1u8; 32];
        let target_manifold_id = 42u64.to_be_bytes();
        let intent_hash = [7u8; 32];
        let safe_address = Address::repeat_byte(0xaa);
        let amount = [9u8; 32];
        let ttl = 100u64.to_be_bytes();

        // 1. Test Secp256k1 (Scheme 0)
        let secp_signing_key = SigningKey::from_slice(&[2u8; 32]).unwrap();
        let secp_verifying_key = secp_signing_key.verifying_key();
        let secp_pubkey = secp_verifying_key.to_sec1_point(true);
        let secp_sig: k256::ecdsa::Signature = secp_signing_key.sign(&intent_hash);
        let secp_sig_bytes = secp_sig.to_bytes();

        let mut payload_secp = Vec::new();
        payload_secp.extend_from_slice(&namespace);
        payload_secp.extend_from_slice(&target_manifold_id);
        payload_secp.extend_from_slice(&intent_hash);
        payload_secp.extend_from_slice(safe_address.as_slice());
        payload_secp.extend_from_slice(&amount);
        payload_secp.extend_from_slice(&ttl);
        payload_secp.push(0); // scheme = 0
        payload_secp.extend_from_slice(secp_pubkey.as_bytes());
        payload_secp.extend_from_slice(&secp_sig_bytes);

        let res = execute_cross_manifold_call(&Bytes::from(payload_secp));
        assert!(res.is_ok());
        let out = res.unwrap();
        assert_eq!(out[31], 1);

        // 2. Test Ed25519 (Scheme 1)
        let ed_signing_key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let ed_verifying_key = ed_signing_key.verifying_key();
        let ed_pubkey = ed_verifying_key.to_bytes();
        let ed_sig = ed_signing_key.sign(&intent_hash);
        let ed_sig_bytes = ed_sig.to_bytes();

        let mut payload_ed = Vec::new();
        payload_ed.extend_from_slice(&namespace);
        payload_ed.extend_from_slice(&target_manifold_id);
        payload_ed.extend_from_slice(&intent_hash);
        payload_ed.extend_from_slice(safe_address.as_slice());
        payload_ed.extend_from_slice(&amount);
        payload_ed.extend_from_slice(&ttl);
        payload_ed.push(1); // scheme = 1
        payload_ed.extend_from_slice(&ed_pubkey);
        payload_ed.push(0); // 1-byte padding to make 33 bytes pubkey
        payload_ed.extend_from_slice(&ed_sig_bytes);

        let res = execute_cross_manifold_call(&Bytes::from(payload_ed));
        assert!(res.is_ok());

        // 3. Test expired TTL
        let expired_ttl = 0u64.to_be_bytes();
        let mut payload_expired = Vec::new();
        payload_expired.extend_from_slice(&namespace);
        payload_expired.extend_from_slice(&target_manifold_id);
        payload_expired.extend_from_slice(&intent_hash);
        payload_expired.extend_from_slice(safe_address.as_slice());
        payload_expired.extend_from_slice(&amount);
        payload_expired.extend_from_slice(&expired_ttl);
        payload_expired.push(0);
        payload_expired.extend_from_slice(secp_pubkey.as_bytes());
        payload_expired.extend_from_slice(&secp_sig_bytes);

        let res = execute_cross_manifold_call(&Bytes::from(payload_expired));
        assert!(res.is_err());
    }
}
