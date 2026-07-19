//! Optional X-Road Standard Relay Server
//! Allows members of an organization to expose a compliant query relay endpoint
//! bridging external X-Road Security Server calls to the Sovereign Reth consensus layer.

use sovereign_consensus::metalex::{BorgOrganization, MetalexManager};

/// Mock X-Road SOAP request header structures.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct XRoadRequestHeader {
    /// The client invoking the request
    pub client: String,
    /// The requested service name
    pub service: String,
    /// Unique query identifier
    pub id: String,
    /// Protocol version (typically "4.0")
    pub protocol_version: String,
}

/// A relay server instance mapping X-Road queries to the consensus layer.
pub struct XRoadRelay {
    /// Reference to the consensus organization manager
    pub metalex_manager: MetalexManager,
}

impl XRoadRelay {
    /// Creates a new X-Road Relay instance.
    pub fn new(metalex_manager: MetalexManager) -> Self {
        Self { metalex_manager }
    }

    /// Handles a SOAP-like X-Road payload query.
    ///
    /// Exposes organization structure to external systems in a signed, auditable format.
    pub fn query_organization_state(&self, org_did: &str, _header: &XRoadRequestHeader) -> Result<String, &'static str> {
        if let Some(org) = self.metalex_manager.orgs.get(org_did) {
            // Build response signed by the organization's did:peer:4 key.
            // In a real system, the server signs using HSM or the peer's private key.
            // We represent the signed payload as a JSON document containing the organization state
            // and a mock cryptographic signature.
            let payload = serde_json::to_string(org).map_err(|_| "Failed to serialize org state")?;
            let mock_signature = format!("signed:did:peer:4:{}", org_did);
            
            let response = serde_json::json!({
                "xroad_response": {
                    "status": "success",
                    "payload": payload,
                    "signature": mock_signature
                }
            });
            
            Ok(response.to_string())
        } else {
            Err("Organization not found in consensus registry")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_xroad_relay_query() {
        let mut metalex_manager = MetalexManager::new();
        let mut agents = HashMap::new();
        agents.insert("did:peer:4:alice".to_string(), "director".to_string());
        
        let org = BorgOrganization {
            did_peer: "did:peer:4:sovereign_co".to_string(),
            equity_token: "0xEquityAddress".to_string(),
            agents,
            is_active: true,
        };
        
        // Setup registry
        let audit = sovereign_consensus::metalex::RealityAudit {
            epoch: 1,
            validator_signatures: vec![vec![1]],
        };
        let _ = metalex_manager.register_or_update_org(org, &audit, 1);
        
        let relay = XRoadRelay::new(metalex_manager);
        let header = XRoadRequestHeader {
            client: "gov-dept-x".to_string(),
            service: "getOrgStructure".to_string(),
            id: "req-12345".to_string(),
            protocol_version: "4.0".to_string(),
        };
        
        let response = relay.query_organization_state("did:peer:4:sovereign_co", &header).unwrap();
        assert!(response.contains("0xEquityAddress"));
        assert!(response.contains("signed:did:peer:4:did:peer:4:sovereign_co"));
    }
}
