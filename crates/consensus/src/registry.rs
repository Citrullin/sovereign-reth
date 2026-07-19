//! DPoT Validator Directory module.

use alloy_primitives::Address;
use std::collections::{HashMap, HashSet};

/// Represents the type of a validator in the DPoT system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorType {
    /// Hardware TEE validator (high security).
    HardwareTEE,
    /// Vanilla Social validator (reputation based).
    VanillaSocial,
}

/// DPoT Validator Directory with TinyMeritRank reputation using did:peer:4.
#[derive(Debug, Clone)]
pub struct ValidatorRegistry {
    /// Active validators mapped to their type.
    validators: HashMap<String, ValidatorType>,
    /// Resolved WireGuard keys mapped by DID.
    peer_keys: HashMap<String, [u8; 32]>,
    /// Mapping from resolved EVM Address to DID.
    address_to_did: HashMap<Address, String>,
    /// The seeds (bootstrap roots) of trust.
    seeds: HashSet<String>,
    /// Directed edges: u_did -> (v_did, weight) representing endorsements.
    endorsements: HashMap<String, HashMap<String, f64>>,
    /// Computed reputation scores for each DID.
    reputation: HashMap<String, f64>,
    /// Minimum reputation required for HardwareTEE validators if enclave is suspected to be compromised.
    pub sgx_reputation_threshold: f64,
    /// Mapping of validator DID -> Set of Manifold IDs they are willing to route to.
    supported_manifolds: HashMap<String, HashSet<u64>>,
    /// Configurable minimum validators required to activate a manifold route.
    pub manifold_quorum_threshold: usize,
}

impl Default for ValidatorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ValidatorRegistry {
    /// Creates a new validator registry and bootstraps with default seeds.
    pub fn new() -> Self {
        let mut registry = Self {
            validators: HashMap::new(),
            peer_keys: HashMap::new(),
            address_to_did: HashMap::new(),
            seeds: HashSet::new(),
            endorsements: HashMap::new(),
            reputation: HashMap::new(),
            sgx_reputation_threshold: 0.0,
            supported_manifolds: HashMap::new(),
            manifold_quorum_threshold: 500, // Default configurable threshold
        };

        // Bootstrap with genesis seeds
        let keys = vec![did_peer::DIDPeerCreateKeys {
            type_: Some(did_peer::DIDPeerKeyType::Ed25519),
            purpose: did_peer::DIDPeerKeys::Verification,
            public_key_multibase: Some("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string()),
        }];
        let (genesis_did, _) = did_peer::DIDPeer::create_peer_did(&keys, None).unwrap();
        let genesis_addr = Address::repeat_byte(0x99);

        registry.seeds.insert(genesis_did.clone());
        registry.validators.insert(genesis_did.clone(), ValidatorType::VanillaSocial);
        registry.peer_keys.insert(genesis_did.clone(), [0x99; 32]);
        registry.address_to_did.insert(genesis_addr, genesis_did.clone());

        // Self-endorsement for genesis seed to keep them in the PageRank loop
        let mut self_end = HashMap::new();
        self_end.insert(genesis_did.clone(), 1.0);
        registry.endorsements.insert(genesis_did, self_end);

        registry.compute_pagerank();
        registry
    }

    /// Resolves EVM Address and WireGuard key from DID and registers as TEE validator.
    pub fn register_sgx_node(&mut self, candidate_did: String) -> Result<(), &'static str> {
        let (addr, wg_key) = self.resolve_did_keys(&candidate_did)?;
        self.validators.insert(candidate_did.clone(), ValidatorType::HardwareTEE);
        self.peer_keys.insert(candidate_did.clone(), wg_key);
        self.address_to_did.insert(addr, candidate_did);
        Ok(())
    }

    /// Proposes a new social validator (creates initial endorsement).
    pub fn propose_validator(&mut self, proposer_addr: Address, candidate_did: String) -> Result<(), &'static str> {
        let _proposer_did = self.address_to_did.get(&proposer_addr)
            .ok_or("Proposer must be an active registered validator")?
            .clone();

        let (candidate_addr, wg_key) = self.resolve_did_keys(&candidate_did)?;
        self.peer_keys.insert(candidate_did.clone(), wg_key);
        self.address_to_did.insert(candidate_addr, candidate_did.clone());

        self.endorse_validator(proposer_addr, candidate_did, 1.0)
    }

    /// Endorses a candidate with a specific weight.
    pub fn endorse_validator(&mut self, endorser_addr: Address, candidate_did: String, weight: f64) -> Result<(), &'static str> {
        let endorser_did = self.address_to_did.get(&endorser_addr)
            .ok_or("Endorser must be an active registered validator")?
            .clone();

        self.endorsements.entry(endorser_did).or_default().insert(candidate_did, weight);
        self.compute_pagerank();
        self.update_active_validators();
        Ok(())
    }

    fn resolve_did_keys(&self, did: &str) -> Result<(Address, [u8; 32]), &'static str> {
        println!("DEBUG: resolving DID {}", did);
        // Resolve using the identity crate on an isolated thread with its own tokio runtime to prevent deadlocks
        let did_str = did.to_string();
        let resolved = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| "Failed to build local tokio runtime")?;
            rt.block_on(sovereign_identity::DidPeer4::resolve(&did_str))
        }).join().map_err(|_| "Thread panic during DID resolution")??;
        println!("DEBUG: resolved DID successfully: {:?}", resolved);
        
        let mut wg_key = [0u8; 32];
        let bytes = &resolved.public_key;
        let len = bytes.len().min(32);
        wg_key[..len].copy_from_slice(&bytes[..len]);

        // Derive EVM Address
        let addr = match resolved.key_type {
            sovereign_identity::KeyType::Secp256k1 => {
                let pk = k256::PublicKey::from_sec1_bytes(&resolved.public_key)
                    .map_err(|_| "Failed to parse public key bytes")?;
                use k256::elliptic_curve::sec1::ToSec1Point;
                let uncompressed = pk.to_sec1_point(false);
                let hash = alloy_primitives::keccak256(&uncompressed.as_bytes()[1..]);
                Address::from_slice(&hash[12..32])
            }
            sovereign_identity::KeyType::Ed25519 => {
                // For Ed25519, hash public key bytes directly to produce EVM Address
                let hash = alloy_primitives::keccak256(&resolved.public_key);
                Address::from_slice(&hash[12..32])
            }
        };

        Ok((addr, wg_key))
    }

    /// Returns the active WireGuard peer keys.
    pub fn active_peers(&self) -> HashMap<[u8; 32], Address> {
        let mut active = HashMap::new();
        for (did, &peer_key) in &self.peer_keys {
            if let Some(val_type) = self.validators.get(did) {
                // If the enclave is suspected to be compromised and reputation threshold is set,
                // verify that the SGX node also possesses sufficient social reputation.
                if *val_type == ValidatorType::HardwareTEE && self.sgx_reputation_threshold > 0.0 {
                    let rep = self.reputation.get(did).copied().unwrap_or(0.0);
                    if rep < self.sgx_reputation_threshold {
                        continue;
                    }
                }
                // Find EVM address for this DID
                if let Some((&addr, _)) = self.address_to_did.iter().find(|(_, d)| *d == did) {
                    active.insert(peer_key, addr);
                }
            }
        }
        active
    }

    /// Registers a manifold that the validator is willing to route to.
    pub fn register_supported_manifold(&mut self, did: &str, target_manifold_id: u64) -> Result<(), &'static str> {
        if !self.validators.contains_key(did) {
            return Err("Only registered validators can declare routing support");
        }
        
        let entry = self.supported_manifolds.entry(did.to_string()).or_insert_with(HashSet::new);
        entry.insert(target_manifold_id);
        
        // Operator Warning if quorum is not met
        let mut total_supporters = 0;
        for manifolds in self.supported_manifolds.values() {
            if manifolds.contains(&target_manifold_id) {
                total_supporters += 1;
            }
        }
        
        if total_supporters < self.manifold_quorum_threshold {
            // Log a warning so the operator knows the route is not yet secure/active
            eprintln!("WARN: [INSUFFICIENT QUORUM] Validator {} registered for manifold {}, but total ({}) is below threshold ({}). Route is not yet secure/active.",
                did, target_manifold_id, total_supporters, self.manifold_quorum_threshold);
        }
        
        Ok(())
    }

    /// Returns the active EVM addresses of validators that route to a specific manifold.
    /// Only returns a route if the total quorum threshold is met.
    pub fn get_routable_validators(&self, target_manifold_id: u64) -> HashSet<Address> {
        let mut routable = HashSet::new();
        let active = self.active_peers();
        
        // Active returns peer_key -> Address. We need to iterate over Address -> DID -> supported
        for addr in active.values() {
            if let Some(did) = self.get_did_by_address(addr) {
                if let Some(manifolds) = self.supported_manifolds.get(&did) {
                    if manifolds.contains(&target_manifold_id) {
                        routable.insert(*addr);
                    }
                }
            }
        }
        
        // Enforce Quorum Threshold
        if routable.len() < self.manifold_quorum_threshold {
            return HashSet::new(); // Route is disabled
        }
        
        routable
    }

    /// Computes TinyMeritRank reputation using Personalized PageRank.
    pub fn compute_pagerank(&mut self) {
        if self.seeds.is_empty() {
            return;
        }

        let d = 0.85; // Damping factor
        let teleport_prob = 1.0 - d;
        let iterations = 20;

        // Collect all unique nodes in the graph
        let mut nodes = HashSet::new();
        for seed in &self.seeds {
            nodes.insert(seed.clone());
        }
        for (u, targets) in &self.endorsements {
            nodes.insert(u.clone());
            for v in targets.keys() {
                nodes.insert(v.clone());
            }
        }

        // Initialize PageRank scores
        let mut pr: HashMap<String, f64> = nodes.iter().map(|addr| (addr.clone(), 1.0 / nodes.len() as f64)).collect();

        // Compute out-going weights
        let mut out_weights: HashMap<String, f64> = HashMap::new();
        for (u, targets) in &self.endorsements {
            let total: f64 = targets.values().sum();
            out_weights.insert(u.clone(), total);
        }

        // Power Iteration
        for _ in 0..iterations {
            let mut next_pr: HashMap<String, f64> = nodes.iter().map(|addr| (addr.clone(), 0.0)).collect();

            for u in &nodes {
                let u_pr = *pr.get(u).unwrap_or(&0.0);
                if let Some(targets) = self.endorsements.get(u) {
                    let total_weight = *out_weights.get(u).unwrap_or(&0.0);
                    if total_weight > 0.0 {
                        for (v, &weight) in targets {
                            let share = (weight / total_weight) * u_pr * d;
                            *next_pr.entry(v.clone()).or_default() += share;
                        }
                    } else {
                        // Distribute to seeds
                        for seed in &self.seeds {
                            *next_pr.entry(seed.clone()).or_default() += (u_pr * d) / self.seeds.len() as f64;
                        }
                    }
                } else {
                    // Distribute to seeds
                    for seed in &self.seeds {
                        *next_pr.entry(seed.clone()).or_default() += (u_pr * d) / self.seeds.len() as f64;
                    }
                }

                // Add teleport probability
                if self.seeds.contains(u) {
                    *next_pr.entry(u.clone()).or_default() += teleport_prob / self.seeds.len() as f64;
                }
            }
            pr = next_pr;
        }

        self.reputation = pr;
    }

    /// Promotes social validators if their reputation exceeds the threshold (0.05).
    fn update_active_validators(&mut self) {
        for (did, &rep) in &self.reputation {
            if rep >= 0.05 && !self.validators.contains_key(did) {
                self.validators.insert(did.clone(), ValidatorType::VanillaSocial);
            }
        }
    }

    /// Applies monthly temporal decay: R_i(j) = (1 - gamma) * R_i(j) + delta_R * gamma
    pub fn apply_temporal_decay(&mut self) {
        let gamma = 0.05;
        let delta_r = 0.05;
        for rep in self.reputation.values_mut() {
            *rep = (1.0 - gamma) * (*rep) + delta_r * gamma;
        }
        self.update_active_validators();
    }

    /// Checks if address is registered and returns its type.
    pub fn get_type_by_address(&self, address: &Address) -> Option<ValidatorType> {
        let did = self.address_to_did.get(address)?;
        self.validators.get(did).copied()
    }

    /// Returns the registered DID of an address.
    pub fn get_did_by_address(&self, address: &Address) -> Option<String> {
        self.address_to_did.get(address).cloned()
    }

    /// Returns the EVM Address associated with a DID.
    pub fn get_address_by_did(&self, did: &str) -> Option<Address> {
        self.address_to_did.iter()
            .find(|(_, d)| *d == did)
            .map(|(&addr, _)| addr)
    }

    /// Returns the reputation of a validator by address.
    pub fn get_reputation_by_address(&self, address: &Address) -> f64 {
        let did = match self.address_to_did.get(address) {
            Some(d) => d,
            None => return 0.0,
        };
        self.reputation.get(did).copied().unwrap_or(0.0)
    }

    /// Sets the reputation score for a DID (used in testing).
    #[cfg(test)]
    pub fn set_reputation(&mut self, did: String, value: f64) {
        self.reputation.insert(did, value);
    }

    /// Adds a mock validator directly (used in testing).
    #[cfg(test)]
    pub fn add_mock_validator(&mut self, did: String, addr: Address, peer_key: [u8; 32]) {
        self.validators.insert(did.clone(), ValidatorType::VanillaSocial);
        self.peer_keys.insert(did.clone(), peer_key);
        self.address_to_did.insert(addr, did);
    }
}

use std::sync::{OnceLock, RwLock};

/// Global static validator registry.
pub static VALIDATOR_REGISTRY: OnceLock<RwLock<ValidatorRegistry>> = OnceLock::new();

/// Returns a static reference to the shared thread-safe validator registry.
pub fn get_registry() -> &'static RwLock<ValidatorRegistry> {
    VALIDATOR_REGISTRY.get_or_init(|| RwLock::new(ValidatorRegistry::new()))
}

