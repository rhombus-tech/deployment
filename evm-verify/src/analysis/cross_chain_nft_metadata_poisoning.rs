/// Cross-Chain NFT Metadata Poisoning Detector
///
/// Detects NFT metadata inconsistencies across chains.
/// Risk: All cross-chain NFT bridges
/// Attack: NFT metadata valid on Chain A, poisoned on Chain B

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossChainNFTMetadataPoisoningVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub poisoning_type: MetadataPoisoningType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MetadataPoisoningType {
    MetadataURIDesync,
    TokenIDConflict,
    MetadataContentManipulation,
}

pub struct CrossChainNFTMetadataPoisoningAnalyzer;

impl CrossChainNFTMetadataPoisoningAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossChainNFTMetadataPoisoningVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_metadata_uri_desync(bytecode) {
            vulnerabilities.push(CrossChainNFTMetadataPoisoningVulnerability {
                severity: SecuritySeverity::High,
                description: "NFT metadata URI differs across chains".to_string(),
                location: "TokenURI query".to_string(),
                poisoning_type: MetadataPoisoningType::MetadataURIDesync,
                impact: "Same NFT points to different metadata on different chains".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_metadata_uri_desync(&self, bytecode: &[u8]) -> bool {
        let token_uri_sig = &[0xc8, 0x7b, 0x56, 0xdd]; // tokenURI
        bytecode.windows(4).any(|w| w == token_uri_sig) &&
        bytecode.windows(50).any(|window| {
            window.contains(&0xf1) && // Cross-chain
            !window.contains(&0x14)   // No URI consistency check
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossChainNFTMetadataPoisoningVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossChainNFTMetadataPoisoning,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Chain NFT Metadata Poisoning: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement cross-chain metadata consistency verification", vuln.location),
        }).collect()
    }
}
