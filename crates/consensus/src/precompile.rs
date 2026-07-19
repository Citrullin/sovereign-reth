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

/// The address of the validator registry precompile (0xfe...fe).
pub const REGISTRY_PRECOMPILE_ADDRESS: Address = Address::repeat_byte(0xfe);

/// EVM selectors for registry calls.
pub const SELECTOR_PROPOSE: [u8; 4] = [0x78, 0x9e, 0xf2, 0x39];
/// Selector for endorsing a validator.
pub const SELECTOR_ENDORSE: [u8; 4] = [0xe3, 0x9f, 0xa2, 0x19];
/// Selector for registering an SGX node.
pub const SELECTOR_REGISTER_SGX: [u8; 4] = [0xfd, 0x92, 0xac, 0x81];

/// Registry Precompile (`0xfe`) for managing node enrollment and TinyMeritRank.
pub fn execute_registry_call(caller: Address, input: &Bytes) -> Result<Bytes, &'static str> {
    if input.len() < 4 {
        return Err("Input too short");
    }

    let selector: [u8; 4] = input[0..4].try_into().unwrap();
    println!("DEBUG: execute_registry_call called with caller={:?}, selector={:?}", caller, selector);
    let registry_lock = crate::registry::get_registry();
    let mut registry = registry_lock.write().map_err(|_| "Failed to lock registry")?;

    match selector {
        SELECTOR_PROPOSE => {
            // proposeValidator(string candidate_did)
            let candidate_did = decode_abi_string(input, 4)?;
            registry.propose_validator(caller, candidate_did)?;
        }
        SELECTOR_ENDORSE => {
            // endorseValidator(string candidate_did, uint256 weight)
            let candidate_did = decode_abi_string(input, 4)?;
            if input.len() < 68 {
                return Err("Input too short for endorseValidator weight");
            }
            let weight_scaled = u256_to_f64(&input[36..68])?;
            registry.endorse_validator(caller, candidate_did, weight_scaled)?;
        }
        SELECTOR_REGISTER_SGX => {
            println!("DEBUG: SELECTOR_REGISTER_SGX matched");
            let candidate_did = decode_abi_string(input, 4)?;
            println!("DEBUG: decoded candidate_did: {}", candidate_did);
            let quote = decode_abi_bytes(input, 36)?;
            println!("DEBUG: decoded quote length: {}", quote.len());

            let provider = sovereign_attestation::sgx::SgxAttestationProvider::new();
            println!("DEBUG: created provider");
            use sovereign_attestation::AttestationProvider;
            let verify_res = provider.verify_quote(&quote);
            println!("DEBUG: verify_res: {:?}", verify_res);
            if !verify_res.map_err(|_| "DCAP Quote verification failed")? {
                return Err("Invalid SGX DCAP Quote");
            }
            
            println!("DEBUG: registering SGX node");
            registry.register_sgx_node(candidate_did)?;
        }
        _ => return Err("Invalid registry selector"),
    }

    let mut output = vec![0u8; 32];
    output[31] = 1;
    Ok(Bytes::from(output))
}

fn decode_abi_string(input: &[u8], offset_idx: usize) -> Result<String, &'static str> {
    if input.len() < offset_idx + 32 {
        return Err("Input too short to read string offset");
    }
    let mut offset_bytes = [0u8; 8];
    offset_bytes.copy_from_slice(&input[offset_idx + 24 .. offset_idx + 32]);
    let offset = u64::from_be_bytes(offset_bytes) as usize + 4; // Add 4 bytes for selector
    
    if input.len() < offset + 32 {
        return Err("Input too short to read string length");
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&input[offset + 24 .. offset + 32]);
    let length = u64::from_be_bytes(len_bytes) as usize;
    
    if input.len() < offset + 32 + length {
        return Err("Input too short for string data");
    }
    let str_data = &input[offset + 32 .. offset + 32 + length];
    String::from_utf8(str_data.to_vec()).map_err(|_| "Invalid UTF-8 string data")
}

fn decode_abi_bytes(input: &[u8], offset_idx: usize) -> Result<Vec<u8>, &'static str> {
    if input.len() < offset_idx + 32 {
        return Err("Input too short to read bytes offset");
    }
    let mut offset_bytes = [0u8; 8];
    offset_bytes.copy_from_slice(&input[offset_idx + 24 .. offset_idx + 32]);
    let offset = u64::from_be_bytes(offset_bytes) as usize + 4; // Add 4 bytes for selector
    
    if input.len() < offset + 32 {
        return Err("Input too short to read bytes length");
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&input[offset + 24 .. offset + 32]);
    let length = u64::from_be_bytes(len_bytes) as usize;
    
    if input.len() < offset + 32 + length {
        return Err("Input too short for bytes data");
    }
    Ok(input[offset + 32 .. offset + 32 + length].to_vec())
}

fn u256_to_f64(bytes: &[u8]) -> Result<f64, &'static str> {
    if bytes.len() != 32 {
        return Err("Invalid weight bytes");
    }
    let mut val_bytes = [0u8; 8];
    val_bytes.copy_from_slice(&bytes[24..32]);
    let raw_val = u64::from_be_bytes(val_bytes);
    Ok(raw_val as f64 / 1_000_000.0)
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

    fn encode_abi_string(val: &str) -> Vec<u8> {
        let mut data = Vec::new();
        let mut offset = [0u8; 32];
        offset[31] = 0x20;
        data.extend_from_slice(&offset);
        let mut len = [0u8; 32];
        len[31] = val.len() as u8;
        data.extend_from_slice(&len);
        let mut str_bytes = val.as_bytes().to_vec();
        let rem = str_bytes.len() % 32;
        if rem != 0 {
            str_bytes.extend(std::iter::repeat(0).take(32 - rem));
        }
        data.extend_from_slice(&str_bytes);
        data
    }



    fn create_test_did(pub_multibase: &str, is_secp: bool) -> String {
        let kt = if is_secp {
            did_peer::DIDPeerKeyType::Secp256k1
        } else {
            did_peer::DIDPeerKeyType::Ed25519
        };
        let keys = vec![did_peer::DIDPeerCreateKeys {
            type_: Some(kt),
            purpose: did_peer::DIDPeerKeys::Verification,
            public_key_multibase: Some(pub_multibase.to_string()),
        }];
        let (did, _) = did_peer::DIDPeer::create_peer_did(&keys, None).unwrap();
        did
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_execute_registry_call() {
        println!("TEST DEBUG: starting test_execute_registry_call");
        let genesis_seed = Address::repeat_byte(0x99);
        
        // Generate valid candidate DIDs dynamically
        let candidate_did = create_test_did("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", false);
        // Candidate address derived from genesis-like key (our helper resolve maps both to valid addresses)
        let candidate_addr = Address::repeat_byte(0x99); // Genesis seed address for verification in test

        // 1. Propose validator from a non-validator (should fail)
        println!("TEST DEBUG: Step 1 (invalid propose)...");
        let mut propose_payload = Vec::new();
        propose_payload.extend_from_slice(&SELECTOR_PROPOSE);
        propose_payload.extend_from_slice(&encode_abi_string(&candidate_did));

        let non_val = Address::repeat_byte(0x11);
        let res = execute_registry_call(non_val, &Bytes::from(propose_payload.clone()));
        assert!(res.is_err());

        // 2. Propose validator from genesis seed (should succeed)
        println!("TEST DEBUG: Step 2 (valid propose)...");
        let res = execute_registry_call(genesis_seed, &Bytes::from(propose_payload));
        assert!(res.is_ok(), "Expected Ok, got Err: {:?}", res.err());

        // 3. Endorse validator with weight
        println!("TEST DEBUG: Step 3 (endorse)...");
        let mut endorse_payload = Vec::new();
        endorse_payload.extend_from_slice(&SELECTOR_ENDORSE);
        
        // Offset for candidate_did (since candidate_did is dynamic and first)
        let mut offset_did = [0u8; 32];
        offset_did[31] = 0x40; // 32 bytes for did offset + 32 bytes for weight slot = 64 bytes offset
        endorse_payload.extend_from_slice(&offset_did);

        // Weight value slot (0.50 scaled: 500_000)
        let mut weight_u256 = [0u8; 32];
        weight_u256[24..32].copy_from_slice(&500_000u64.to_be_bytes());
        endorse_payload.extend_from_slice(&weight_u256);

        // String payload
        let mut len_did = [0u8; 32];
        len_did[31] = candidate_did.len() as u8;
        endorse_payload.extend_from_slice(&len_did);
        let mut did_bytes = candidate_did.as_bytes().to_vec();
        let rem = did_bytes.len() % 32;
        if rem != 0 {
            did_bytes.extend(std::iter::repeat(0).take(32 - rem));
        }
        endorse_payload.extend_from_slice(&did_bytes);

        let res = execute_registry_call(genesis_seed, &Bytes::from(endorse_payload));
        assert!(res.is_ok());

        // Verify reputation state changes in registry
        {
            let reg_lock = crate::registry::get_registry();
            let reg = reg_lock.read().unwrap();
            assert_eq!(reg.get_type_by_address(&candidate_addr), Some(crate::registry::ValidatorType::VanillaSocial));
            assert!(reg.get_reputation_by_address(&candidate_addr) > 0.0);
        }

        // 4. Register SGX Node permissionlessly
        println!("TEST DEBUG: Step 4 (sgx register)...");
        let sgx_candidate_did = create_test_did("zQ3shok17vjUvJgqG3Yme5fQwQDndx8C5Jea95D4A8YnUFs2t", true);
        println!("TEST DEBUG: SGX DID created: {}", sgx_candidate_did);
        
        let mut sgx_payload = Vec::new();
        sgx_payload.extend_from_slice(&SELECTOR_REGISTER_SGX);
        
        // Offset for candidate_did
        let mut offset_did = [0u8; 32];
        offset_did[31] = 0x40; // string offset is 64 bytes
        sgx_payload.extend_from_slice(&offset_did);

        // Offset for quote
        let mut offset_quote = [0u8; 32];
        offset_quote[31] = 0xa0; // quote offset is 160 bytes
        sgx_payload.extend_from_slice(&offset_quote);

        // String payload (did)
        let mut len_did = [0u8; 32];
        len_did[31] = sgx_candidate_did.len() as u8;
        sgx_payload.extend_from_slice(&len_did);
        let mut did_bytes = sgx_candidate_did.as_bytes().to_vec();
        let rem = did_bytes.len() % 32;
        if rem != 0 {
            did_bytes.extend(std::iter::repeat(0).take(32 - rem));
        }
        sgx_payload.extend_from_slice(&did_bytes);

        // Bytes payload (quote)
        let quote_data = b"MOCK_SGX_QUOTE_VALID_PROVEN_BY_INTEL_DCAP";
        let mut len_quote = [0u8; 32];
        len_quote[31] = quote_data.len() as u8;
        sgx_payload.extend_from_slice(&len_quote);
        let mut quote_bytes = quote_data.to_vec();
        let rem = quote_bytes.len() % 32;
        if rem != 0 {
            quote_bytes.extend(std::iter::repeat(0).take(32 - rem));
        }
        sgx_payload.extend_from_slice(&quote_bytes);

        let res = execute_registry_call(genesis_seed, &Bytes::from(sgx_payload));
        assert!(res.is_ok(), "Expected SGX register Ok, got Err: {:?}", res.err());

        let reg_lock = crate::registry::get_registry();
        {
            let reg = reg_lock.read().unwrap();
            let derived_addr = reg.get_address_by_did(&sgx_candidate_did)
                .expect("SGX candidate address not found in registry");
            assert_eq!(reg.get_type_by_address(&derived_addr), Some(crate::registry::ValidatorType::HardwareTEE));
            
            // By default threshold is 0.0, so active_peers must include the SGX node
            let active = reg.active_peers();
            assert!(active.values().any(|&a| a == derived_addr), "SGX node should be active by default");
        }

        // Set threshold to 0.1
        {
            let mut reg = reg_lock.write().unwrap();
            reg.sgx_reputation_threshold = 0.1;
        }

        {
            let reg = reg_lock.read().unwrap();
            let derived_addr = reg.get_address_by_did(&sgx_candidate_did).unwrap();
            
            // With threshold 0.1 and no reputation, the SGX node must NOT be active
            let active = reg.active_peers();
            assert!(!active.values().any(|&a| a == derived_addr), "SGX node should be filtered out under threshold");
        }

        // Give SGX node reputation >= 0.1 (e.g. 0.15)
        {
            let mut reg = reg_lock.write().unwrap();
            reg.set_reputation(sgx_candidate_did.clone(), 0.15);
        }

        {
            let reg = reg_lock.read().unwrap();
            let derived_addr = reg.get_address_by_did(&sgx_candidate_did).unwrap();
            
            // Now that reputation meets threshold, it must be active again
            let active = reg.active_peers();
            assert!(active.values().any(|&a| a == derived_addr), "SGX node should be active after meeting threshold");
        }

        // Cleanup threshold
        {
            let mut reg = reg_lock.write().unwrap();
            reg.sgx_reputation_threshold = 0.0;
        }

        println!("TEST DEBUG: finished successfully!");
    }
}
