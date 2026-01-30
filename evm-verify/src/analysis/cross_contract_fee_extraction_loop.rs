/// Cross-Contract Fee Extraction Loop Detector
///
/// Detects circular fee extraction patterns across protocols.
/// Risk: Composable DeFi protocols

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractFeeExtractionLoopVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub loop_type: FeeLoopType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FeeLoopType {
    CircularFeeCollection,
    RecursiveFeeExtraction,
    CrossProtocolFeeArbitrage,
    CompoundingFeeExploitation,
}

pub struct CrossContractFeeExtractionLoopAnalyzer;

impl CrossContractFeeExtractionLoopAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractFeeExtractionLoopVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_circular_fee_collection(bytecode) {
            vulnerabilities.push(CrossContractFeeExtractionLoopVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Fee collection can create circular loops across protocols".to_string(),
                location: "Fee collection".to_string(),
                loop_type: FeeLoopType::CircularFeeCollection,
                impact: "Recursive fee collection can drain protocol funds".to_string(),
            });
        }

        if self.has_recursive_fee_extraction(bytecode) {
            vulnerabilities.push(CrossContractFeeExtractionLoopVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Fees can be recursively extracted through protocol composition".to_string(),
                location: "Fee calculation".to_string(),
                loop_type: FeeLoopType::RecursiveFeeExtraction,
                impact: "Compounding fees can exceed intended amounts".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_circular_fee_collection(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(50).any(|window| {
            window.contains(&0xf1) && // CALL
            window.contains(&0x02) && // MUL (fee calc)
            window.contains(&0x56) && // JUMP (loop)
            window.iter().filter(|&&op| op == 0xf1).count() >= 2
        })
    }

    fn has_recursive_fee_extraction(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(60).any(|window| {
            window.contains(&0x02) && // MUL (fee)
            window.contains(&0xf1) && // External call
            window.contains(&0x02) && // Another MUL (compounding)
            !window.contains(&0x11)   // No cap check
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractFeeExtractionLoopVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractFeeExtractionLoop,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Contract Fee Extraction Loop: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement fee caps and reentrancy guards", vuln.location),
        }).collect()
    }
}
