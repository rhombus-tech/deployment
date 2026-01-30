use crate::bytecode::{SecurityFinding, SecuritySeverity};


pub struct NftCollateralLiquidationFrontrunDetector;

impl NftCollateralLiquidationFrontrunDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            if self.has_liquidation_logic(bytecode, i) && self.lacks_frontrun_protection(bytecode, i) {
                findings.push(SecurityFinding {
                    severity: SecuritySeverity::High,
                    description: "NFT collateral liquidation frontrun: liquidation logic without frontrun protection allows MEV extraction".to_string(),
                    pc: i,
                    confidence: 0.87,
                });
            }
            i += 1;
        }

        findings
    }

    fn has_liquidation_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let mut has_comparison = false;
        let mut has_transfer = false;
        let mut has_sload = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x14 => has_comparison = true,
                    0xf1 | 0xfa => has_transfer = true,
                    0x54 => has_sload = true,
                    _ => {}
                }
            }
        }

        has_comparison && has_transfer && has_sload
    }

    fn lacks_frontrun_protection(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        for offset in 1..=lookback {
            if pos >= offset + 1 {
                if bytecode[pos - offset] == 0x42 && bytecode[pos - offset + 1] == 0x01 {
                    return false;
                }
            }
        }
        true
    }
}
