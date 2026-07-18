//! Deterministic fake quote for Vanilla nodes.

use crate::AttestationProvider;

/// Mock Attestation Provider for Vanilla Social nodes.
#[derive(Debug, Default)]
pub struct MockAttestationProvider;

impl MockAttestationProvider {
    /// Creates a new mock attestation provider.
    pub fn new() -> Self {
        Self
    }
}

impl AttestationProvider for MockAttestationProvider {
    fn generate_quote(&self, report_data: &[u8]) -> Result<Vec<u8>, String> {
        // Return a deterministic "fake" quote based on report data
        let mut quote = b"MOCK_QUOTE:".to_vec();
        quote.extend_from_slice(report_data);
        Ok(quote)
    }

    fn verify_quote(&self, quote: &[u8]) -> Result<bool, String> {
        // Just verify it starts with our mock prefix
        Ok(quote.starts_with(b"MOCK_QUOTE:"))
    }
}
