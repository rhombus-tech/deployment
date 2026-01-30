pub struct CompoundMakerdaoLiquidationRaceDetector {
    bytecode: Vec<u8>,
}

impl CompoundMakerdaoLiquidationRaceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_liquidation_race_condition() {
            findings.push("Liquidation race: Cross-protocol liquidation race between Compound and MakerDAO".to_string());
        }

        if self.has_collateral_reuse() {
            findings.push("Liquidation race: Same collateral used across multiple protocols".to_string());
        }

        if self.has_flash_loan_liquidation() {
            findings.push("Liquidation race: Flash loan liquidation manipulation detected".to_string());
        }

        findings
    }

    fn has_liquidation_race_condition(&self) -> bool {
        let liquidation_patterns = [b"liquidate", b"Liquidate", b"seize"];
        let has_liquidation = liquidation_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_liquidation {
            let protocol_patterns = [b"compound", b"Compound", b"maker", b"Maker", b"cdp"];
            let protocol_count = protocol_patterns.iter().filter(|p| self.bytecode.windows(p.len()).any(|w| w == *p)).count();
            
            return protocol_count >= 2;
        }
        
        false
    }

    fn has_collateral_reuse(&self) -> bool {
        let collateral_patterns = [b"collateral", b"deposit", b"lock"];
        let has_collateral = collateral_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_collateral {
            let call_count = self.bytecode.iter().filter(|&&b| b == 0xf1 || b == 0xf4).count();
            return call_count > 4;
        }
        
        false
    }

    fn has_flash_loan_liquidation(&self) -> bool {
        let flash_patterns = [b"flash", b"borrow"];
        let liquidation_patterns = [b"liquidate", b"seize"];
        
        let has_flash = flash_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        let has_liquidation = liquidation_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        has_flash && has_liquidation
    }
}
