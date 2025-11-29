/// Balance Manipulation Detector
/// Detects contracts vulnerable to balance manipulation via airdrops or force-sends

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceManipulationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub pc: usize,
}

pub struct BalanceManipulationDetector {
    bytecode: Vec<u8>,
}

impl BalanceManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BalanceManipulationVulnerability> {
        let mut vulns = Vec::new();
        vulns.extend(self.detect_balance_equality_checks());
        vulns.extend(self.detect_balance_based_logic());
        vulns
    }

    /// Detect strict balance equality checks
    fn detect_balance_equality_checks(&self) -> Vec<BalanceManipulationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        // Pattern: BALANCE followed by EQ (strict equality)
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x31 {  // BALANCE
                // Check if followed by EQ (dangerous!)
                if self.has_eq_after(pc, 10) {
                    vulns.push(BalanceManipulationVulnerability {
                        severity: SecuritySeverity::Critical,
                        description: "Contract uses strict balance equality check - can be broken by airdrop".to_string(),
                        exploit_scenario: "Balance manipulation attack:\n\
                            1. Contract requires: address(this).balance == expectedBalance\n\
                            2. Attacker airdrops 1 wei\n\
                            3. Equality check fails\n\
                            4. Contract permanently locked/broken\n\
                            \n\
                            Or attacker forces ETH via selfdestruct".to_string(),
                        remediation: "Use >= instead of ==:\n\
                            // DON'T:\n\
                            require(address(this).balance == totalDeposits);\n\
                            \n\
                            // DO:\n\
                            require(address(this).balance >= totalDeposits);".to_string(),
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

    /// Detect business logic that depends on exact balance
    fn detect_balance_based_logic(&self) -> Vec<BalanceManipulationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // BALANCE used in calculation (potential manipulation)
            if opcode == 0x31 {  // BALANCE
                // Followed by arithmetic (MUL, DIV, etc.)
                if self.has_arithmetic_after(pc, 20) {
                    // Check if this affects critical logic (JUMPI nearby)
                    if self.has_jumpi_after(pc, 50) {
                        vulns.push(BalanceManipulationVulnerability {
                            severity: SecuritySeverity::High,
                            description: "Business logic depends on contract balance - manipulable via airdrop".to_string(),
                            exploit_scenario: "Balance-based logic manipulation:\n\
                                1. Contract: rewardRate = address(this).balance / totalStaked\n\
                                2. Attacker airdrops large amount\n\
                                3. rewardRate inflates\n\
                                4. Attacker stakes small amount\n\
                                5. Claims inflated rewards\n\
                                6. Drains contract".to_string(),
                            remediation: "Track balances internally:\n\
                                uint256 public rewardPool;  // Track explicitly\n\
                                \n\
                                function addRewards() payable {\n\
                                rewardPool += msg.value;  // Don't use address(this).balance\n\
                                }".to_string(),
                            pc,
                        });
                    }
                }
            }

            pc += 1;
            if pc > 0 && self.bytecode[pc-1] >= 0x60 && self.bytecode[pc-1] <= 0x7F {
                pc += (self.bytecode[pc-1] - 0x5F) as usize;
            }
        }

        vulns
    }

    fn has_eq_after(&self, pc: usize, window: usize) -> bool {
        let end = (pc + window).min(self.bytecode.len());
        self.bytecode[pc..end].iter().any(|&b| b == 0x14)  // EQ
    }

    fn has_arithmetic_after(&self, pc: usize, window: usize) -> bool {
        let end = (pc + window).min(self.bytecode.len());
        self.bytecode[pc..end].iter().any(|&b| 
            b == 0x01 ||  // ADD
            b == 0x02 ||  // MUL
            b == 0x03 ||  // SUB
            b == 0x04     // DIV
        )
    }

    fn has_jumpi_after(&self, pc: usize, window: usize) -> bool {
        let end = (pc + window).min(self.bytecode.len());
        self.bytecode[pc..end].iter().any(|&b| b == 0x57)  // JUMPI
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_balance_equality() {
        let bytecode = vec![
            0x31,        // BALANCE
            0x60, 0x64,  // PUSH1 100
            0x14,        // EQ (balance == 100) - VULNERABLE!
        ];
        let detector = BalanceManipulationDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(!vulns.is_empty());
    }

    #[test]
    fn test_safe_balance_check() {
        let bytecode = vec![
            0x31,        // BALANCE
            0x60, 0x64,  // PUSH1 100
            0x10,        // LT (balance < 100) - Safe
        ];
        let detector = BalanceManipulationDetector::new(bytecode);
        let vulns = detector.detect_balance_equality_checks();
        assert!(vulns.is_empty(), "Should not flag >= checks");
    }
}
