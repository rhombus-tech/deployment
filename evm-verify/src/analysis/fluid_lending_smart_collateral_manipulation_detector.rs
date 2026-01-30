use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct FluidLendingSmartCollateralManipulationDetector {
    bytecode: Vec<u8>,
}

impl FluidLendingSmartCollateralManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_smart_collateral_oracle_manipulation() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: "Smart collateral pricing can be manipulated through oracle attacks or flash loans, allowing undercollateralized borrows.".to_string(),
                pc,
                confidence: 0.90,
            });
        }

        findings
    }

    fn detect_smart_collateral_oracle_manipulation(&self) -> Option<usize> {
        let bytecode = &self.bytecode;

        for i in 0..bytecode.len().saturating_sub(40) {
            if bytecode[i] == 0xFA { // STATICCALL
                let mut has_collateral_calc = false;
                let mut has_borrow = false;

                for j in i+1..std::cmp::min(i+35, bytecode.len()) {
                    if bytecode[j] == 0x02 { has_collateral_calc = true; } // MUL
                    if bytecode[j] == 0xF1 { has_borrow = true; } // CALL
                }

                if has_collateral_calc && has_borrow {
                    return Some(i);
                }
            }
        }

        None
    }
}
