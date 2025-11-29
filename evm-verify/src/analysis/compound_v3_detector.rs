/// Compound v3 Base Token Risk Detector
/// Detects vulnerabilities specific to Compound v3 architecture
/// Critical for: Compound v3 integrations, base token accounting

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundV3Vulnerability {
    pub vulnerability_type: CompoundV3IssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompoundV3IssueType {
    BaseTokenAccountingError,      // Base token balance accounting
    BorrowCapBypass,               // Exceed borrow cap limits
    LiquidationThresholdManipulation, // Manipulate liquidation
    CollateralFactorExploit,       // Exploit collateral factors
    SupplyCapBypass,               // Exceed supply caps
}

pub struct CompoundV3Detector {
    bytecode: Vec<u8>,
}

impl CompoundV3Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CompoundV3Vulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_compound_v3_integration() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_base_token_issues());
        vulnerabilities.extend(self.detect_cap_bypass());

        vulnerabilities
    }

    fn detect_base_token_issues(&self) -> Vec<CompoundV3Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Supply/borrow without proper base token accounting
        for i in 0..self.bytecode.len().saturating_sub(30) {
            let supply = [0x61, 0x7a, 0xec, 0xf1]; // supply()
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &supply {
                if !self.has_base_balance_check(i) {
                    vulnerabilities.push(CompoundV3Vulnerability {
                        vulnerability_type: CompoundV3IssueType::BaseTokenAccountingError,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Compound v3 supply without base token balance validation".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Supply collateral to Compound v3\n\
                            2. Base token accounting not updated properly\n\
                            3. Can borrow more than collateral allows\n\
                            4. Protocol insolvency risk\n\n\
                            Fix: Validate baseToken balances after each operation",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_cap_bypass(&self) -> Vec<CompoundV3Vulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Borrow without cap check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            let borrow = [0xa4, 0x15, 0x03, 0x8d]; // borrow()
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &borrow {
                if !self.has_cap_validation(i) {
                    vulnerabilities.push(CompoundV3Vulnerability {
                        vulnerability_type: CompoundV3IssueType::BorrowCapBypass,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "Borrow operation without cap validation".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Borrow exceeds configured cap\n\
                            2. No validation of totalBorrows vs borrowCap\n\
                            3. Risk concentration in single asset\n\
                            4. Market manipulation possible\n\n\
                            Fix: require(totalBorrows + amount <= borrowCap)",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn is_compound_v3_integration(&self) -> bool {
        let supply = [0x61, 0x7a, 0xec, 0xf1]; // supply()
        let borrow = [0xa4, 0x15, 0x03, 0x8d]; // borrow()
        self.bytecode.windows(4).any(|w| w == supply || w == borrow)
    }

    fn has_base_balance_check(&self, pos: usize) -> bool {
        // Look for STATICCALL to get base token balance
        for i in pos..pos.saturating_add(50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0xFA { // STATICCALL
                return true;
            }
        }
        false
    }

    fn has_cap_validation(&self, pos: usize) -> bool {
        // Look for comparison (cap check)
        for i in pos..pos.saturating_add(40).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 {
                return true;
            }
        }
        false
    }
}
