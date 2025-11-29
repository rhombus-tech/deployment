/// Return Bomb Detector
/// Detects DOS via excessive return data from malicious contracts

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReturnBombVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub pc: usize,
}

pub struct ReturnBombDetector {
    bytecode: Vec<u8>,
}

impl ReturnBombDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ReturnBombVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        // Pattern: CALL/STATICCALL followed by RETURNDATASIZE/RETURNDATACOPY without size check
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Check for external calls
            if opcode == 0xF1 || opcode == 0xFA {  // CALL or STATICCALL
                // Check if returndata is copied without size validation
                if self.has_unsafe_returndata_copy_after(pc) {
                    vulns.push(ReturnBombVulnerability {
                        severity: SecuritySeverity::Medium,
                        description: "External call copies return data without size limit - DOS via return bomb".to_string(),
                        exploit_scenario: "Return bomb attack:\n\
                            1. Contract calls untrusted contract\n\
                            2. (bool success, bytes memory data) = target.call()\n\
                            3. Malicious contract returns 10MB of data\n\
                            4. RETURNDATACOPY costs millions of gas\n\
                            5. Transaction runs out of gas\n\
                            6. All legitimate calls fail = DOS\n\
                            \n\
                            Cost: ~3 gas per byte, 10MB = 30M gas".to_string(),
                        remediation: "Limit return data size:\n\
                            // Option 1: Don't copy return data\n\
                            (bool success, ) = target.call{gas: 50000}(\"\");\n\
                            \n\
                            // Option 2: Limit returndata copy\n\
                            assembly {\n\
                                let size := returndatasize()\n\
                                if gt(size, 0x1000) { size := 0x1000 }  // Max 4KB\n\
                                returndatacopy(ptr, 0, size)\n\
                            }".to_string(),
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

    fn has_unsafe_returndata_copy_after(&self, call_pc: usize) -> bool {
        let end = (call_pc + 100).min(self.bytecode.len());
        
        // Look for RETURNDATASIZE or RETURNDATACOPY after the call
        for i in call_pc..end {
            if i >= self.bytecode.len() {
                break;
            }
            
            let opcode = self.bytecode[i];
            
            // RETURNDATACOPY (0x3E) or RETURNDATASIZE (0x3D)
            if opcode == 0x3E || opcode == 0x3D {
                // Check if there's a size limit check (comparison before copy)
                if !self.has_size_check_between(call_pc, i) {
                    return true;
                }
            }
        }
        
        false
    }

    fn has_size_check_between(&self, start: usize, end: usize) -> bool {
        // Look for GT/LT comparison (size limit check)
        let end = end.min(self.bytecode.len());
        self.bytecode[start..end].iter().any(|&b| 
            b == 0x10 ||  // LT
            b == 0x11     // GT
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_return_bomb() {
        let bytecode = vec![
            0xF1,        // CALL
            0x3D,        // RETURNDATASIZE
            0x3E,        // RETURNDATACOPY (no size check!)
        ];
        let detector = ReturnBombDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(!vulns.is_empty(), "Should detect return bomb vulnerability");
    }

    #[test]
    fn test_safe_return_handling() {
        let bytecode = vec![
            0xF1,        // CALL
            0x3D,        // RETURNDATASIZE
            0x10,        // LT (size check!)
            0x3E,        // RETURNDATACOPY
        ];
        let detector = ReturnBombDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(vulns.is_empty(), "Should not flag safe return handling");
    }
}
