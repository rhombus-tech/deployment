/// EXTCODESIZE Bypass Detector
/// Detects contract existence checks that can be bypassed during construction

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtcodesizeBypassVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub pc: usize,
}

pub struct ExtcodesizeBypassDetector {
    bytecode: Vec<u8>,
}

impl ExtcodesizeBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ExtcodesizeBypassVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        // Pattern: EXTCODESIZE check used for critical logic
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x3B {  // EXTCODESIZE
                // Check if result is used in conditional (JUMPI)
                if self.has_jumpi_after(pc, 20) {
                    vulns.push(ExtcodesizeBypassVulnerability {
                        severity: SecuritySeverity::Medium,
                        description: "Contract uses EXTCODESIZE for validation - can be bypassed in constructor".to_string(),
                        exploit_scenario: "EXTCODESIZE bypass attack:\n\
                            1. Contract checks: require(addr.code.length > 0)\n\
                            2. Intended to block EOAs, allow only contracts\n\
                            3. Attacker deploys malicious contract\n\
                            4. In constructor, calls target BEFORE code deployed\n\
                            5. EXTCODESIZE returns 0 during construction!\n\
                            6. Check bypassed, attacker gets through\n\
                            \n\
                            Real pattern:\n\
                            contract Attack {\n\
                                constructor(Target t) {\n\
                                    t.restrictedFunction();  // EXTCODESIZE(this) == 0!\n\
                                }\n\
                            }".to_string(),
                        remediation: "Don't rely on EXTCODESIZE alone:\n\
                            // VULNERABLE:\n\
                            require(msg.sender.code.length > 0, 'Only contracts');\n\
                            \n\
                            // BETTER: Use combination of checks\n\
                            require(msg.sender == tx.origin || msg.sender.code.length > 0);\n\
                            \n\
                            // OR: Whitelist specific contracts\n\
                            require(allowedContracts[msg.sender], 'Not allowed');\n\
                            \n\
                            // OR: Check both code length AND hash\n\
                            require(msg.sender.code.length > 0 && msg.sender.codehash != 0);".to_string(),
                        pc,
                    });
                }
                
                // Also check if EXTCODESIZE is used with ISZERO (common pattern)
                if self.has_iszero_after(pc, 5) {
                    vulns.push(ExtcodesizeBypassVulnerability {
                        severity: SecuritySeverity::Low,
                        description: "EXTCODESIZE == 0 check - vulnerable to constructor bypass".to_string(),
                        exploit_scenario: "Constructor bypass for 'only EOA' check:\n\
                            1. Contract checks: require(addr.code.length == 0)  // Only EOAs\n\
                            2. Attacker calls from constructor\n\
                            3. During construction, code.length == 0\n\
                            4. Passes as EOA, but is actually contract\n\
                            5. Bypasses intended restriction".to_string(),
                        remediation: "Use tx.origin for EOA checks:\n\
                            require(msg.sender == tx.origin, 'Only EOAs');".to_string(),
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

    fn has_jumpi_after(&self, pc: usize, window: usize) -> bool {
        let end = (pc + window).min(self.bytecode.len());
        self.bytecode[pc..end].iter().any(|&b| b == 0x57)  // JUMPI
    }

    fn has_iszero_after(&self, pc: usize, window: usize) -> bool {
        let end = (pc + window).min(self.bytecode.len());
        self.bytecode[pc..end].iter().any(|&b| b == 0x15)  // ISZERO
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_extcodesize_check() {
        let bytecode = vec![
            0x3B,        // EXTCODESIZE
            0x60, 0x00,  // PUSH1 0
            0x57,        // JUMPI (conditional on code size)
        ];
        let detector = ExtcodesizeBypassDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(!vulns.is_empty(), "Should detect EXTCODESIZE bypass risk");
    }
}
