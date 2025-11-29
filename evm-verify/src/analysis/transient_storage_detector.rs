/// Transient Storage (EIP-1153) Vulnerability Detector
/// Detects TSTORE/TLOAD reentrancy and data persistence issues

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransientStorageVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub pc: usize,
}

pub struct TransientStorageDetector {
    bytecode: Vec<u8>,
}

impl TransientStorageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TransientStorageVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        // Pattern: TSTORE (0x5D) or TLOAD (0x5C) - EIP-1153 opcodes
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // TLOAD followed by external call = reentrancy risk
            if opcode == 0x5C {  // TLOAD
                if self.has_external_call_after(pc, 50) {
                    if !self.has_reentrancy_guard_pattern(pc) {
                        vulns.push(TransientStorageVulnerability {
                            severity: SecuritySeverity::Critical,
                            description: "TLOAD used before external call - transient storage reentrancy".to_string(),
                            exploit_scenario: "Transient storage reentrancy (EIP-1153):\n\
                                1. Contract uses TLOAD to check reentrancy guard\n\
                                2. Guard stored in transient storage (TSTORE)\n\
                                3. External call made\n\
                                4. Attacker reenters from callback\n\
                                5. Transient storage cleared between calls!\n\
                                6. Guard bypassed, reentrancy succeeds\n\
                                \n\
                                CRITICAL: TSTORE/TLOAD cleared at end of transaction.\n\
                                NOT persistent like SSTORE!".to_string(),
                            remediation: "Use regular storage for reentrancy guards:\n\
                                // VULNERABLE (transient storage):\n\
                                assembly {\n\
                                    if tload(0) { revert(0, 0) }\n\
                                    tstore(0, 1)  // Will be cleared!\n\
                                }\n\
                                \n\
                                // SAFE (persistent storage):\n\
                                require(!locked, 'Reentrancy');\n\
                                locked = true;  // SSTORE persists\n\
                                \n\
                                // OR: Use transient storage only for single-call guards\n\
                                // within same transaction frame".to_string(),
                            pc,
                        });
                    }
                }
            }

            // TSTORE used for critical data
            if opcode == 0x5D {  // TSTORE
                if self.is_critical_data_pattern(pc) {
                    vulns.push(TransientStorageVulnerability {
                        severity: SecuritySeverity::High,
                        description: "TSTORE used for critical data - will not persist across transactions".to_string(),
                        exploit_scenario: "Transient storage data loss:\n\
                            1. Contract stores important state in TSTORE\n\
                            2. Expects data to persist\n\
                            3. Transaction ends\n\
                            4. TSTORE cleared automatically!\n\
                            5. Next transaction reads TLOAD = 0\n\
                            6. Logic fails or security bypassed".to_string(),
                        remediation: "Use SSTORE for persistent data:\n\
                            // Only use TSTORE for:\n\
                            // 1. Within-transaction temporary data\n\
                            // 2. Gas optimization for single-tx computations\n\
                            // 3. NOT for security-critical state".to_string(),
                        pc,
                    });
                }
            }

            // Pattern: TLOAD in view function
            if opcode == 0x5C && self.is_in_view_function(pc) {
                vulns.push(TransientStorageVulnerability {
                    severity: SecuritySeverity::Medium,
                    description: "TLOAD used in view function - will always return 0".to_string(),
                    exploit_scenario: "View function transient storage bug:\n\
                        1. View function uses TLOAD\n\
                        2. View functions are staticcall\n\
                        3. Transient storage not shared across calls\n\
                        4. TLOAD always returns 0\n\
                        5. Incorrect view results".to_string(),
                    remediation: "Don't use TLOAD in view/pure functions".to_string(),
                    pc,
                });
            }

            pc += 1;
            if pc > 0 && self.bytecode[pc-1] >= 0x60 && self.bytecode[pc-1] <= 0x7F {
                pc += (self.bytecode[pc-1] - 0x5F) as usize;
            }
        }

        vulns
    }

    fn has_external_call_after(&self, pc: usize, window: usize) -> bool {
        let end = (pc + window).min(self.bytecode.len());
        self.bytecode[pc..end].iter().any(|&b| 
            b == 0xF1 ||  // CALL
            b == 0xFA ||  // STATICCALL
            b == 0xF4     // DELEGATECALL
        )
    }

    fn has_reentrancy_guard_pattern(&self, pc: usize) -> bool {
        // Check for SLOAD/SSTORE pattern (persistent guard)
        let end = (pc + 100).min(self.bytecode.len());
        self.bytecode[pc..end].windows(2).any(|w| 
            w[0] == 0x54 && w[1] == 0x55  // SLOAD + SSTORE
        )
    }

    fn is_critical_data_pattern(&self, pc: usize) -> bool {
        // Check if TSTORE is used with conditional logic (likely critical)
        let start = pc.saturating_sub(20);
        let end = (pc + 20).min(self.bytecode.len());
        
        self.bytecode[start..end].iter().any(|&b| 
            b == 0x57  // JUMPI (conditional)
        )
    }

    fn is_in_view_function(&self, pc: usize) -> bool {
        // Heuristic: view functions often have STATICCALL nearby
        let start = pc.saturating_sub(100);
        self.bytecode[start..pc].iter().any(|&b| b == 0xFA)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_transient_reentrancy() {
        let bytecode = vec![
            0x5C,        // TLOAD
            0xF1,        // CALL (external)
        ];
        let detector = TransientStorageDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(!vulns.is_empty(), "Should detect transient storage reentrancy");
    }
}
