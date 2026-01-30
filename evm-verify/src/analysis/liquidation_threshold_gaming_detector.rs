/// Liquidation Threshold Gaming Detector
/// Detects manipulation of liquidation thresholds to avoid liquidation

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidationThresholdGamingVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

pub struct LiquidationThresholdGamingDetector {
    bytecode: Vec<u8>,
}

impl LiquidationThresholdGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LiquidationThresholdGamingVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(250) {
            if self.is_liquidation_check(pc) {
                if !self.has_threshold_protection(pc, 200) {
                    vulnerabilities.push(LiquidationThresholdGamingVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: format!(
                            "Liquidation threshold check at PC {} can be manipulated via price or collateral gaming",
                            pc
                        ),
                        exploit_scenario:
                            "Threshold Gaming Attack:\n\
                             1. User has position: 100 ETH collateral, 80 ETH borrowed\n\
                             2. Liquidation threshold: 85% (liquidate if debt/collateral > 0.85)\n\
                             3. ETH price drops, position now at 84% (near threshold)\n\
                             4. User flash-deposits 1000 ETH collateral\n\
                             5. Ratio improves to 8% (well below threshold)\n\
                             6. Liquidation check passes\n\
                             7. User withdraws 1000 ETH in same transaction\n\
                             8. Back to 84%, avoids liquidation\n\
                             9. Repeat to indefinitely delay liquidation\n\n\
                             Fix: Check sustained collateral levels over time".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn is_liquidation_check(&self, pc: usize) -> bool {
        if pc + 150 >= self.bytecode.len() { return false; }
        let mut has_div = false;
        let mut has_comparison = false;
        for i in pc..(pc + 150).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x04 { has_div = true; }
            if has_div && matches!(self.bytecode[i], 0x10 | 0x11) { has_comparison = true; }
        }
        has_div && has_comparison
    }

    fn has_threshold_protection(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range / 2);
        let end = (pc + range / 2).min(self.bytecode.len());
        for i in start..end {
            if self.bytecode[i] == 0x42 { return true; } // TIMESTAMP check
        }
        false
    }
}
