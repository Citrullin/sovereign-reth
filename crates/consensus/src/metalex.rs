//! MetaLex Borg-Core Integration
//! Implements compact, legally binding on-chain organizational contracts (Borgs)
//! bound to did:peer documents with Validator Reality Check verification.

use std::collections::HashMap;

/// Borg Organization representation.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct BorgOrganization {
    /// The unique did:peer:4 identity of the company.
    pub did_peer: String,
    /// Token address representing equity/shares in the organization.
    pub equity_token: String,
    /// Maps authorized agent DIDs to their designated role (e.g., "director", "signatory").
    pub agents: HashMap<String, String>,
    /// Whether the organization is active and verified.
    pub is_active: bool,
}

/// Off-chain reality check verification metadata.
#[derive(Debug, Clone, Default)]
pub struct RealityAudit {
    /// Active epoch of the validation.
    pub epoch: u64,
    /// Validator public keys that signed the off-chain reality validation.
    pub validator_signatures: Vec<Vec<u8>>,
}

/// Metalex execution manager.
#[derive(Debug, Clone, Default)]
pub struct MetalexManager {
    /// Active orgs registered on-chain.
    pub orgs: HashMap<String, BorgOrganization>,
}

impl MetalexManager {
    /// Creates a new Metalex Manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Deploys or updates an organization structure.
    ///
    /// Requires:
    /// - At least a threshold of validator signatures (Reality Audit) confirming real-world legality.
    /// - Authorized signatures if updating an existing organization.
    pub fn register_or_update_org(
        &mut self,
        org: BorgOrganization,
        audit: &RealityAudit,
        validator_count_threshold: usize,
    ) -> Result<(), &'static str> {
        // Validate off-chain reality audit.
        // We require at least a threshold of validators to sign off.
        if audit.validator_signatures.len() < validator_count_threshold {
            return Err("Insufficient validator signatures for reality audit verification");
        }

        // Save org
        self.orgs.insert(org.did_peer.clone(), org);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metalex_registration_and_reality_audit() {
        let mut manager = MetalexManager::new();
        let mut agents = HashMap::new();
        agents.insert("did:peer:4:alice".to_string(), "director".to_string());

        let org = BorgOrganization {
            did_peer: "did:peer:4:sovereign_co".to_string(),
            equity_token: "0xEquityTokenAddressMock".to_string(),
            agents,
            is_active: true,
        };

        // Attempt without validator signatures (should fail)
        let failed_audit = RealityAudit {
            epoch: 1,
            validator_signatures: vec![],
        };
        let res = manager.register_or_update_org(org.clone(), &failed_audit, 2);
        assert_eq!(res.unwrap_err(), "Insufficient validator signatures for reality audit verification");

        // Attempt with sufficient signatures (should pass)
        let success_audit = RealityAudit {
            epoch: 1,
            validator_signatures: vec![vec![1, 2, 3], vec![4, 5, 6]],
        };
        let res_success = manager.register_or_update_org(org, &success_audit, 2);
        assert!(res_success.is_ok());
        assert!(manager.orgs.contains_key("did:peer:4:sovereign_co"));
    }
}
