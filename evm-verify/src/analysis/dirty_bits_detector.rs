/// Dirty High-Order Bits Detector
/// Detects type confusion via uncleaned high-order bits in type conversions

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirtyBitsVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub pc: usize,
}

pub struct DirtyBitsDetector {
    bytecode: Vec<u8>,
}

impl DirtyBitsDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DirtyBitsVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        // Pattern: Type conversions without masking
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for CALLDATALOAD (loading 32 bytes)
            if opcode == 0x35 {
                // Check if used directly in address context without AND mask
                if self.used_as_address_without_mask(pc) {
                    vulns.push(DirtyBitsVulnerability {
                        severity: SecuritySeverity::Medium,
                        description: "Type conversion without cleaning high-order bits - potential type confusion".to_string(),
                        exploit_scenario: "Dirty bits type confusion:\n\
                            1. Contract: address target = address(uint160(uint256(data)))\n\
                            2. If high bits not cleaned: 0x0000...DEAD...1234567890123456789012345678901234567890\n\
                            3. Should be:                0x0000000000000000000000001234567890123456789012345678901234567890\n\
                            4. Dirty high bits can cause:\n\
                               - Hash collisions\n\
                               - Mapping key mismatches\n\
                               - Comparison failures\n\
                               - Unexpected storage slots\n\
                            \n\
                            Solidity 0.4.x was vulnerable to this.".to_string(),
                        remediation: "Always mask when converting to smaller types:\n\
                            // VULNERABLE (old Solidity):\n\
                            address target = address(uint256(data));\n\
                            \n\
                            // SAFE:\n\
                            address target = address(uint160(uint256(data)));\n\
                            \n\
                            // SAFER (explicit mask):\n\
                            address target = address(uint160(uint256(data) & 0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF));\n\
                            \n\
                            // Or use assembly:\n\
                            assembly {\n\
                                target := and(data, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)\n\
                            }".to_string(),
                        pc,
                    });
                }
            }

            // Look for byte/uint8 conversions
            if opcode == 0x35 || opcode == 0x51 {  // CALLDATALOAD or MLOAD
                if self.used_as_small_int_without_mask(pc) {
                    vulns.push(DirtyBitsVulnerability {
                        severity: SecuritySeverity::Low,
                        description: "uint8/byte conversion without masking - may have dirty high bits".to_string(),
                        exploit_scenario: "Small int dirty bits:\n\
                            1. uint8 value = uint8(largeNumber);\n\
                            2. If not masked: 0x123456...FF\n\
                            3. Should be: 0xFF\n\
                            4. Comparisons may fail unexpectedly".to_string(),
                        remediation: "Mask to appropriate bit size:\n\
                            uint8 value = uint8(data & 0xFF);".to_string(),
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

    fn used_as_address_without_mask(&self, load_pc: usize) -> bool {
        let end = (load_pc + 50).min(self.bytecode.len());
        
        // Check if used in address context (CALL, STATICCALL, etc.)
        let has_address_usage = self.bytecode[load_pc..end].iter().any(|&b| 
            b == 0xF1 ||  // CALL
            b == 0xFA ||  // STATICCALL
            b == 0xF4 ||  // DELEGATECALL
            b == 0x31     // BALANCE
        );

        // Check if there's an AND mask for address (160 bits)
        let has_address_mask = self.bytecode[load_pc..end].windows(2).any(|w| 
            w[0] == 0x16  // AND opcode
        );

        has_address_usage && !has_address_mask
    }

    fn used_as_small_int_without_mask(&self, load_pc: usize) -> bool {
        let end = (load_pc + 30).min(self.bytecode.len());
        
        // Check if used in comparison or arithmetic
        let has_usage = self.bytecode[load_pc..end].iter().any(|&b| 
            b == 0x10 ||  // LT
            b == 0x11 ||  // GT
            b == 0x14 ||  // EQ
            b == 0x01 ||  // ADD
            b == 0x03     // SUB
        );

        // Check if there's a mask (AND)
        let has_mask = self.bytecode[load_pc..end].iter().any(|&b| b == 0x16);

        has_usage && !has_mask
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_dirty_address_bits() {
        let bytecode = vec![
            0x35,        // CALLDATALOAD
            0xF1,        // CALL (using as address without mask!)
        ];
        let detector = DirtyBitsDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(!vulns.is_empty(), "Should detect dirty bits in address conversion");
    }

    #[test]
    fn test_safe_masked_conversion() {
        let bytecode = vec![
            0x35,        // CALLDATALOAD
            0x16,        // AND (masking!)
            0xF1,        // CALL
        ];
        let detector = DirtyBitsDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        assert!(vulns.is_empty(), "Should not flag masked conversions");
    }
}
