/// Cross-Contract Metadata Manipulation Detector
///
/// Detects vulnerabilities where non-financial metadata affects protocol behavior.
/// Risk: NFT-Fi, metadata-dependent protocols ($10B+ TVL)

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractMetadataManipulationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub metadata_type: MetadataType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MetadataType {
    NFTMetadataInfluence,
    TokenNameSymbolManipulation,
    URIManipulation,
    ExternalMetadataDependency,
}

pub struct CrossContractMetadataManipulationAnalyzer;

impl CrossContractMetadataManipulationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractMetadataManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_nft_metadata_influence(bytecode) {
            vulnerabilities.push(CrossContractMetadataManipulationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "NFT metadata from external contracts affects financial logic".to_string(),
                location: "Metadata usage".to_string(),
                metadata_type: MetadataType::NFTMetadataInfluence,
                impact: "Mutable metadata can manipulate collateral valuations".to_string(),
            });
        }

        if self.has_uri_manipulation_risk(bytecode) {
            vulnerabilities.push(CrossContractMetadataManipulationVulnerability {
                severity: SecuritySeverity::Low,
                description: "External URI data used in protocol logic".to_string(),
                location: "URI handling".to_string(),
                metadata_type: MetadataType::URIManipulation,
                impact: "URI changes can affect protocol behavior".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_nft_metadata_influence(&self, bytecode: &[u8]) -> bool {
        let token_uri_sig = &[0xc8, 0x7b, 0x56, 0xdd]; // tokenURI()
        bytecode.windows(4).any(|w| w == token_uri_sig) &&
        bytecode.contains(&0x02) // MUL (used in calculation)
    }

    fn has_uri_manipulation_risk(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(30).any(|window| {
            window.contains(&0xfa) && // External call
            window.contains(&0xc8) && // Likely URI sig
            window.contains(&0x57)    // JUMPI (affects logic)
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractMetadataManipulationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractMetadataManipulation,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Contract Metadata Manipulation: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Avoid using mutable metadata in financial logic", vuln.location),
        }).collect()
    }
}
