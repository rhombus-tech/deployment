/// Cross-Contract Gas Market Manipulation Detector (EIP-1559)
///
/// Detects base fee manipulation affecting cross-protocol operations.
/// Risk: All EIP-1559 chains, DoS via gas market attacks
/// Attack: Spam to raise base fee, affecting dependent protocols

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractGasMarketManipulationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub manipulation_type: GasMarketManipulationType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GasMarketManipulationType {
    BaseFeeSpike,
    GasLimitDoS,
    PriorityFeeManipulation,
    CrossProtocolGasDependency,
}

pub struct CrossContractGasMarketManipulationAnalyzer;

impl CrossContractGasMarketManipulationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractGasMarketManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_base_fee_dependency(bytecode) {
            vulnerabilities.push(CrossContractGasMarketManipulationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Protocol operations dependent on base fee across chains".to_string(),
                location: "Gas calculation".to_string(),
                manipulation_type: GasMarketManipulationType::BaseFeeSpike,
                impact: "Base fee manipulation DoS cross-protocol operations".to_string(),
            });
        }

        if self.has_gas_limit_dos_risk(bytecode) {
            vulnerabilities.push(CrossContractGasMarketManipulationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Cross-protocol operations without gas limit protection".to_string(),
                location: "Gas handling".to_string(),
                manipulation_type: GasMarketManipulationType::GasLimitDoS,
                impact: "Out-of-gas DoS cascades across protocols".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_base_fee_dependency(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(40).any(|window| {
            window.contains(&0x48) && // BASEFEE
            window.contains(&0xf1) && // External call
            !window.contains(&0x10)   // No bounds check
        })
    }

    fn has_gas_limit_dos_risk(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(30).any(|window| {
            window.contains(&0x5a) && // GAS
            window.contains(&0xf1) && // CALL
            !window.contains(&0x11)   // No gas limit
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractGasMarketManipulationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractGasMarketManipulation,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Contract Gas Market Manipulation: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement gas price bounds and limits", vuln.location),
        }).collect()
    }
}
