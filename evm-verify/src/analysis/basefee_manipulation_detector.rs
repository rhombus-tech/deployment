/// Base Fee Manipulation Detector (EIP-1559)
/// Detects vulnerabilities in contracts relying on block.basefee

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseFeeVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub pc: usize,
}

pub struct BaseFeeManipulationDetector {
    bytecode: Vec<u8>,
}

impl BaseFeeManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BaseFeeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        // EIP-1559: BASEFEE opcode = 0x48
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x48 {  // BASEFEE
                // Used in conditional (access control or pricing)
                if self.is_used_in_conditional(pc) {
                    vulns.push(BaseFeeVulnerability {
                        severity: SecuritySeverity::High,
                        description: "Contract uses block.basefee in conditional logic - manipulable by miners".to_string(),
                        exploit_scenario: "Base fee manipulation:\n\
                            1. Contract requires: if (block.basefee < threshold) {...}\n\
                            2. Miner/builder can influence basefee\n\
                            3. By controlling block fullness:\n\
                               - Full block → basefee increases\n\
                               - Empty block → basefee decreases\n\
                            4. Miner can game the condition\n\
                            5. Bypass access control or get better pricing\n\
                            \n\
                            POST-MERGE: Block builders have MORE control\n\
                            Can strategically fill blocks for profit".to_string(),
                        remediation: "Don't use basefee for security:\n\
                            // VULNERABLE:\n\
                            require(block.basefee < 50 gwei, 'Gas too high');\n\
                            \n\
                            // BETTER: Use oracle for gas prices\n\
                            uint256 maxGasPrice = gasPriceOracle.getMaxPrice();\n\
                            require(tx.gasprice <= maxGasPrice);\n\
                            \n\
                            // OR: Don't restrict based on gas at all".to_string(),
                        pc,
                    });
                }

                // Used in pricing calculations
                if self.is_used_in_arithmetic(pc) {
                    vulns.push(BaseFeeVulnerability {
                        severity: SecuritySeverity::Medium,
                        description: "Contract uses block.basefee in pricing - can be gamed for arbitrage".to_string(),
                        exploit_scenario: "Base fee pricing manipulation:\n\
                            1. Protocol: fee = baseAmount * block.basefee\n\
                            2. Builder can manipulate basefee\n\
                            3. Low basefee = cheap fees\n\
                            4. High basefee = expensive fees\n\
                            5. Arbitrage between different fee regimes\n\
                            \n\
                            Example: Dynamic fee protocol\n\
                            - Uses basefee as market signal\n\
                            - Builder games it for profit extraction".to_string(),
                        remediation: "Use time-weighted average or oracle:\n\
                            // Better: TWAP of basefee over last N blocks\n\
                            uint256 avgBaseFee = getAverageBaseFee(100);\n\
                            \n\
                            // Or: Cap the impact\n\
                            uint256 cappedBaseFee = min(block.basefee, MAX_BASEFEE);".to_string(),
                        pc,
                    });
                }

                // Used with GASPRICE for comparison
                if self.has_gasprice_comparison(pc) {
                    vulns.push(BaseFeeVulnerability {
                        severity: SecuritySeverity::Low,
                        description: "Contract compares basefee with gasprice - miner tip extraction".to_string(),
                        exploit_scenario: "Priority fee extraction:\n\
                            1. tx.gasprice = basefee + priority_fee\n\
                            2. Contract: if (tx.gasprice > basefee) { give_bonus() }\n\
                            3. Builder can set basefee low\n\
                            4. Same priority fee = higher relative bonus\n\
                            5. Users pay more than expected".to_string(),
                        remediation: "Don't incentivize high gas prices:\n\
                            // Avoid bonuses based on gas price\n\
                            // Users shouldn't pay extra for speed in your contract".to_string(),
                        pc,
                    });
                }
            }

            pc += 1;
            if pc > 0 && self.bytecode[pc-1] >= 0x60 && self.bytecode[pc-1] <= 0x7F {
                pc += (self.bytecode[pc-1] - 0x5F) as usize;
            }
        }

        vulns
    }

    fn is_used_in_conditional(&self, basefee_pc: usize) -> bool {
        let end = (basefee_pc + 30).min(self.bytecode.len());
        
        // Look for comparison + JUMPI pattern
        self.bytecode[basefee_pc..end].windows(2).any(|w| 
            (w[0] == 0x10 || w[0] == 0x11 || w[0] == 0x14) &&  // LT, GT, EQ
            w[1] == 0x57  // JUMPI
        )
    }

    fn is_used_in_arithmetic(&self, basefee_pc: usize) -> bool {
        let end = (basefee_pc + 20).min(self.bytecode.len());
        
        // Look for arithmetic operations
        self.bytecode[basefee_pc..end].iter().any(|&b| 
            b == 0x01 ||  // ADD
            b == 0x02 ||  // MUL
            b == 0x03 ||  // SUB
            b == 0x04 ||  // DIV
            b == 0x05     // SDIV
        )
    }

    fn has_gasprice_comparison(&self, basefee_pc: usize) -> bool {
        let start = basefee_pc.saturating_sub(20);
        let end = (basefee_pc + 20).min(self.bytecode.len());
        
        // Look for GASPRICE opcode (0x3A) near BASEFEE
        self.bytecode[start..end].iter().any(|&b| b == 0x3A)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_basefee_conditional() {
        let bytecode = vec![
            0x48,        // BASEFEE
            0x10,        // LT
            0x57,        // JUMPI (conditional!)
        ];
        let detector = BaseFeeManipulationDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(!vulns.is_empty(), "Should detect basefee in conditional");
    }
}
