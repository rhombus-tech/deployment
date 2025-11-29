/// Morpho Blue Vault Exploit Detector
/// Detects vulnerabilities specific to Morpho Blue lending protocol
/// Critical for: Morpho Blue integrations, MetaMorpho vaults

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MorphoBlueVulnerability {
    pub vulnerability_type: MorphoBlueIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MorphoBlueIssueType {
    VaultAllocationManipulation,   // Vault allocation exploit
    RiskCuratorCollusion,          // Risk curator manipulation
    LiquidationQueueGaming,        // Liquidation queue frontrunning
    SupplyCapBypass,               // Supply cap circumvention
    CrossMarketArbitrage,          // Cross-market rate arbitrage
    OracleManipulationRisk,        // Oracle price manipulation
}

pub struct MorphoBlueDetector {
    bytecode: Vec<u8>,
}

impl MorphoBlueDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MorphoBlueVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_morpho_integration() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_allocation_issues());
        vulnerabilities.extend(self.detect_liquidation_issues());

        vulnerabilities
    }

    fn detect_allocation_issues(&self) -> Vec<MorphoBlueVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Vault allocation without proper validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_vault_allocation(i) {
                if !self.has_allocation_limits(i) {
                    vulnerabilities.push(MorphoBlueVulnerability {
                        vulnerability_type: MorphoBlueIssueType::VaultAllocationManipulation,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Morpho vault allocation without limits".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. MetaMorpho vault reallocates capital\n\
                            2. No validation of allocation percentages\n\
                            3. Curator concentrates funds in risky market\n\
                            4. Single market failure = vault insolvency\n\n\
                            Fix: Enforce max allocation per market",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_liquidation_issues(&self) -> Vec<MorphoBlueVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Liquidation without MEV protection
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_liquidation_call(i) {
                if !self.has_mev_protection(i) {
                    vulnerabilities.push(MorphoBlueVulnerability {
                        vulnerability_type: MorphoBlueIssueType::LiquidationQueueGaming,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "Morpho liquidation without MEV protection".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Position becomes liquidatable\n\
                            2. No MEV protection on liquidation\n\
                            3. Searchers frontrun liquidation\n\
                            4. User receives worse execution\n\n\
                            Fix: Use commit-reveal or private mempool",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn is_morpho_integration(&self) -> bool {
        // Look for Morpho Blue function signatures
        let supply = [0x9d, 0x21, 0x26, 0xbf]; // supply()
        let borrow = [0x1e, 0x83, 0xd0, 0x9c]; // borrow()
        let reallocate = [0x87, 0xfe, 0x3d, 0x4a]; // reallocate()
        
        self.bytecode.windows(4).any(|w| w == supply || w == borrow || w == reallocate)
    }

    fn has_vault_allocation(&self, pos: usize) -> bool {
        // Look for allocation function
        let reallocate = [0x87, 0xfe, 0x3d, 0x4a];
        pos + 4 <= self.bytecode.len() && &self.bytecode[pos..pos+4] == &reallocate
    }

    fn has_allocation_limits(&self, pos: usize) -> bool {
        // Look for percentage/limit check
        for i in pos..pos.saturating_add(40).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 { // LT or GT
                return true;
            }
        }
        false
    }

    fn has_liquidation_call(&self, pos: usize) -> bool {
        // Look for liquidate function
        let liquidate = [0x7c, 0x02, 0x9a, 0x3e];
        pos + 4 <= self.bytecode.len() && &self.bytecode[pos..pos+4] == &liquidate
    }

    fn has_mev_protection(&self, pos: usize) -> bool {
        // Look for commit hash or private submission
        for i in pos.saturating_sub(30)..pos {
            if self.bytecode[i] == 0x20 { // KECCAK256 (commit-reveal)
                return true;
            }
        }
        false
    }
}
