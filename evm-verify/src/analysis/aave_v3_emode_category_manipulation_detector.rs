use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AaveV3EmodeVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct AaveV3EmodeCategoryManipulationDetector {
    bytecode: Vec<u8>,
}

impl AaveV3EmodeCategoryManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<AaveV3EmodeVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_emode_category_switch_exploit());
        vulnerabilities.extend(self.detect_ltv_manipulation_via_emode());
        vulnerabilities.extend(self.detect_liquidation_threshold_bypass());

        vulnerabilities
    }

    fn detect_emode_category_switch_exploit(&self) -> Vec<AaveV3EmodeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (eMode category change)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_category_update = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_category_update {
                    let has_health_factor_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_collateral_validation = window.iter().filter(|&&b| b == 0x54).count() >= 3; // Multiple SLOAD
                    let has_category_compatibility = window.iter().any(|&b| b == 0x14); // EQ check
                    
                    if !has_health_factor_check || !has_collateral_validation {
                        vulns.push(AaveV3EmodeVulnerability {
                            pc,
                            vulnerability_type: "EmodeCategorySwitchExploit".to_string(),
                            description: format!(
                                "Aave V3 eMode category change at PC {} without health factor validation. Attack: user borrows in \
                                eMode category 1 (ETH, 97% LTV), switches to category 0 (general, 80% LTV) without repaying, instantly \
                                undercollateralized. Missing: health factor must remain >1 after category switch, borrowed assets must \
                                be compatible with new category. Should validate: newHealthFactor >= 1 && allBorrowsInNewCategory.",
                                pc
                            ),
                            confidence: 0.88,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_ltv_manipulation_via_emode(&self) -> Vec<AaveV3EmodeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (borrow operation)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_borrow_amount = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_borrow_amount {
                    let has_emode_ltv_check = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                    let has_category_specific_limit = window.iter().any(|&b| b == 0x02); // MUL (LTV calculation)
                    
                    if !has_emode_ltv_check {
                        vulns.push(AaveV3EmodeVulnerability {
                            pc,
                            vulnerability_type: "LTVManipulationViaEmode".to_string(),
                            description: format!(
                                "Borrow at PC {} doesn't enforce eMode-specific LTV limits. Aave V3 eMode allows 97% LTV for correlated \
                                assets (stETH/ETH) vs 80% general. Attack: deposit collateral in general mode, switch to eMode, borrow \
                                up to 97%, switch back to general mode, over-borrowed. Missing: LTV check must use current eMode category, \
                                validate borrowed amount <= collateral * eModeLTV. Should enforce category-specific borrowing power limits.",
                                pc
                            ),
                            confidence: 0.86,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_liquidation_threshold_bypass(&self) -> Vec<AaveV3EmodeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (liquidation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_liquidation = window.iter().any(|&b| matches!(b, 0xF1 | 0xF4)); // CALL, DELEGATECALL
                
                if has_liquidation {
                    let has_emode_threshold = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    let has_category_aware = window.iter().any(|&b| b == 0x20); // KECCAK256 (category slot)
                    
                    if !has_emode_threshold || !has_category_aware {
                        vulns.push(AaveV3EmodeVulnerability {
                            pc,
                            vulnerability_type: "LiquidationThresholdBypass".to_string(),
                            description: format!(
                                "Liquidation at PC {} uses wrong threshold for eMode positions. General mode: 85% threshold, eMode: 98% \
                                threshold. Attack: liquidator triggers liquidation using 85% threshold on eMode position that's healthy at \
                                98%, unfair liquidation. Or borrower exploits by staying above 85% but below 98%, avoiding intended liquidation. \
                                Missing: liquidation threshold must match position's eMode category. Should check: \
                                healthFactor < (eMode ? 0.98 : 0.85).",
                                pc
                            ),
                            confidence: 0.84,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }
}
