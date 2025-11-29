/// Aave v3 E-Mode Exploit Detector
/// Detects E-Mode (Efficiency Mode) specific vulnerabilities
/// Critical for: Aave v3 lending protocol integrations

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AaveEModeVulnerability {
    pub vulnerability_type: AaveEModeIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AaveEModeIssueType {
    EModeCategoryManipulation,     // Manipulate E-Mode category assignment
    CollateralSwitchingExploit,    // Exploit collateral category switching
    IsolationModeBypass,           // Bypass isolation mode restrictions
    EModeRatioExploitation,        // Exploit higher LTV in E-Mode
}

pub struct AaveV3EModeDetector {
    bytecode: Vec<u8>,
}

impl AaveV3EModeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AaveEModeVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_aave_integration() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_emode_manipulation());
        vulnerabilities.extend(self.detect_category_switching());

        vulnerabilities
    }

    fn detect_emode_manipulation(&self) -> Vec<AaveEModeVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: setUserEMode without validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            let set_emode = [0x28, 0xdd, 0x2d, 0x45]; // setUserEMode
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &set_emode {
                if !self.has_category_validation(i) {
                    vulnerabilities.push(AaveEModeVulnerability {
                        vulnerability_type: AaveEModeIssueType::EModeCategoryManipulation,
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: "E-Mode category switch without proper validation".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. User deposits ETH, borrows stablecoins\n\
                            2. Switches to stablecoin E-Mode (higher LTV)\n\
                            3. Borrows more than normal mode allows\n\
                            4. Switches back before liquidation\n\
                            5. Over-borrowed position\n\n\
                            Fix: Validate health factor after E-Mode switch",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_category_switching(&self) -> Vec<AaveEModeVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Supply/borrow with E-Mode interactions
        for i in 0..self.bytecode.len().saturating_sub(30) {
            let supply = [0x61, 0x7a, 0xec, 0xf1]; // supply()
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &supply {
                if self.has_emode_interaction_nearby(i) && !self.has_health_factor_check(i) {
                    vulnerabilities.push(AaveEModeVulnerability {
                        vulnerability_type: AaveEModeIssueType::CollateralSwitchingExploit,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "Collateral supply with E-Mode without health check".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Supply collateral in E-Mode category\n\
                            2. Max borrow in E-Mode (high LTV)\n\
                            3. Withdraw partial collateral\n\
                            4. Health factor not recalculated properly\n\
                            5. Under-collateralized position\n\n\
                            Fix: Recalculate health factor after any operation",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn is_aave_integration(&self) -> bool {
        let supply = [0x61, 0x7a, 0xec, 0xf1]; // supply()
        let borrow = [0xa4, 0x15, 0x03, 0x8d]; // borrow()
        self.bytecode.windows(4).any(|w| w == supply || w == borrow)
    }

    fn has_category_validation(&self, pos: usize) -> bool {
        // Look for SLOAD (reading E-Mode category)
        for i in pos..pos.saturating_add(40).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x54 { // SLOAD
                return true;
            }
        }
        false
    }

    fn has_emode_interaction_nearby(&self, pos: usize) -> bool {
        let set_emode = [0x28, 0xdd, 0x2d, 0x45];
        for i in pos.saturating_sub(100)..pos.saturating_add(100).min(self.bytecode.len().saturating_sub(4)) {
            if &self.bytecode[i..i+4] == &set_emode {
                return true;
            }
        }
        false
    }

    fn has_health_factor_check(&self, pos: usize) -> bool {
        // Look for STATICCALL (getUserAccountData)
        for i in pos..pos.saturating_add(50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0xFA { // STATICCALL
                return true;
            }
        }
        false
    }
}
