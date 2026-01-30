/// Cross-Contract MEV Coordination Detector
///
/// Detects MEV extraction patterns coordinated across multiple protocols.
/// Risk: $500M+ in annual MEV, coordinated sandwich attacks
/// Real exploits: jaredfromsubway.eth ($30M+), MEV bots

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractMEVCoordinationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub mev_type: MEVCoordinationType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MEVCoordinationType {
    CoordinatedSandwich,
    CrossProtocolFrontrun,
    MultiProtocolArbitrage,
    AtomicMEVExtraction,
    BuilderCoordination,
}

pub struct CrossContractMEVCoordinationAnalyzer;

impl CrossContractMEVCoordinationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractMEVCoordinationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_coordinated_sandwich(bytecode) {
            vulnerabilities.push(CrossContractMEVCoordinationVulnerability {
                severity: SecuritySeverity::High,
                description: "Sandwich attack vulnerability across multiple DEXs".to_string(),
                location: "Multi-DEX swap".to_string(),
                mev_type: MEVCoordinationType::CoordinatedSandwich,
                impact: "MEV bots can sandwich across Uniswap→1inch→Curve atomically".to_string(),
            });
        }

        if self.has_cross_protocol_frontrun(bytecode) {
            vulnerabilities.push(CrossContractMEVCoordinationVulnerability {
                severity: SecuritySeverity::High,
                description: "Frontrun vulnerability across protocol boundaries".to_string(),
                location: "Cross-protocol operation".to_string(),
                mev_type: MEVCoordinationType::CrossProtocolFrontrun,
                impact: "Atomically frontrun operations spanning multiple protocols".to_string(),
            });
        }

        if self.has_atomic_mev_extraction(bytecode) {
            vulnerabilities.push(CrossContractMEVCoordinationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Atomic MEV extraction opportunity across protocols".to_string(),
                location: "Atomic operation".to_string(),
                mev_type: MEVCoordinationType::AtomicMEVExtraction,
                impact: "Single transaction extracts MEV from multiple protocols".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_coordinated_sandwich(&self, bytecode: &[u8]) -> bool {
        // Multiple swaps across protocols without slippage protection
        bytecode.windows(100).any(|window| {
            window.iter().filter(|&&op| op == 0xf1).count() >= 3 && // 3+ calls
            !window.contains(&0x10) // No slippage check
        })
    }

    fn has_cross_protocol_frontrun(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(60).any(|window| {
            window.contains(&0xf1) && // External call
            window.contains(&0x42) && // TIMESTAMP (timing)
            !window.contains(&0x03)   // No time delay protection
        })
    }

    fn has_atomic_mev_extraction(&self, bytecode: &[u8]) -> bool {
        let external_calls = bytecode.iter().filter(|&&op| op == 0xf1).count();
        external_calls >= 4 && // Multiple protocols
        bytecode.contains(&0x02) // Profit calculation
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractMEVCoordinationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractMEVCoordination,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Contract MEV Coordination: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement MEV protection and private transactions", vuln.location),
        }).collect()
    }
}
