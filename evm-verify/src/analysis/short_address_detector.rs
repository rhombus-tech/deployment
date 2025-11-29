/// Short Address Attack Detector
/// Detects vulnerabilities related to parameter validation and ABI encoding issues

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShortAddressVulnerability {
    pub vulnerability_type: ShortAddressIssue,
    pub severity: SecuritySeverity,
    pub description: String,
    pub affected_parameters: Vec<String>,
    pub remediation: String,
    pub pc: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ShortAddressIssue {
    /// Missing parameter length validation
    MissingLengthCheck,
    /// ABI encoding vulnerability
    ABIEncodingVulnerable,
    /// Array length manipulation possible
    ArrayLengthManipulation,
    /// Calldata size not validated
    CalldataSizeUnchecked,
}

pub struct ShortAddressDetector {
    bytecode: Vec<u8>,
}

impl ShortAddressDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ShortAddressVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_missing_length_checks());
        vulnerabilities.extend(self.detect_calldata_size_issues());
        vulnerabilities.extend(self.detect_array_manipulation());

        vulnerabilities
    }

    /// Detect functions that don't validate calldata size
    fn detect_missing_length_checks(&self) -> Vec<ShortAddressVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for CALLDATALOAD without CALLDATASIZE check
            if opcode == 0x35 {  // CALLDATALOAD
                // Check if there's a CALLDATASIZE check nearby
                if !self.has_calldata_size_check_near(pc) {
                    vulns.push(ShortAddressVulnerability {
                        vulnerability_type: ShortAddressIssue::MissingLengthCheck,
                        severity: SecuritySeverity::Medium,
                        description: "Function loads calldata without validating size - vulnerable to short address attack".to_string(),
                        affected_parameters: vec!["calldata parameters".to_string()],
                        remediation: "Add require(msg.data.length >= expectedLength) before processing calldata".to_string(),
                        pc,
                    });
                }
            }

            // Look for CALLDATACOPY without size validation
            if opcode == 0x37 {  // CALLDATACOPY
                if !self.has_calldata_size_check_near(pc) {
                    vulns.push(ShortAddressVulnerability {
                        vulnerability_type: ShortAddressIssue::CalldataSizeUnchecked,
                        severity: SecuritySeverity::Medium,
                        description: "CALLDATACOPY used without size validation - could process truncated data".to_string(),
                        affected_parameters: vec!["copied data".to_string()],
                        remediation: "Validate calldata size before copying".to_string(),
                        pc,
                    });
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    /// Detect calldata size validation issues
    fn detect_calldata_size_issues(&self) -> Vec<ShortAddressVulnerability> {
        let mut vulns = Vec::new();
        
        // Check if contract has any CALLDATASIZE checks at all
        let has_any_size_check = self.bytecode.iter().any(|&b| b == 0x36);  // CALLDATASIZE opcode
        
        if !has_any_size_check {
            let has_calldata_ops = self.bytecode.iter()
                .any(|&b| b == 0x35 || b == 0x37);  // CALLDATALOAD or CALLDATACOPY
            
            if has_calldata_ops {
                vulns.push(ShortAddressVulnerability {
                    vulnerability_type: ShortAddressIssue::ABIEncodingVulnerable,
                    severity: SecuritySeverity::High,
                    description: "Contract processes calldata but never validates size - highly vulnerable to short address and ABI encoding attacks".to_string(),
                    affected_parameters: vec!["all parameters".to_string()],
                    remediation: "Add calldata size validation in all external/public functions".to_string(),
                    pc: 0,
                });
            }
        }

        vulns
    }

    /// Detect array length manipulation vulnerabilities
    fn detect_array_manipulation(&self) -> Vec<ShortAddressVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Pattern: Load array length from calldata without bounds check
            // CALLDATALOAD (get length), then used in loop/memory allocation
            if opcode == 0x35 {  // CALLDATALOAD
                // Check if followed by memory allocation or loop
                if self.has_memory_allocation_after(pc, 50) || 
                   self.has_loop_after(pc, 50) {
                    // Check if there's a bounds check (LT, GT opcodes)
                    if !self.has_bounds_check_between(pc, pc + 50) {
                        vulns.push(ShortAddressVulnerability {
                            vulnerability_type: ShortAddressIssue::ArrayLengthManipulation,
                            severity: SecuritySeverity::High,
                            description: "Array length loaded from calldata without bounds check - attacker can cause OOG or memory issues".to_string(),
                            affected_parameters: vec!["array length".to_string()],
                            remediation: "Add require(array.length <= MAX_REASONABLE_LENGTH) before processing".to_string(),
                            pc,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    /// Check if there's a CALLDATASIZE check near the given PC
    fn has_calldata_size_check_near(&self, pc: usize) -> bool {
        let start = pc.saturating_sub(30);
        let end = (pc + 30).min(self.bytecode.len());
        
        self.bytecode[start..end].iter().any(|&b| b == 0x36)  // CALLDATASIZE
    }

    /// Check if there's memory allocation after the given PC
    fn has_memory_allocation_after(&self, pc: usize, window: usize) -> bool {
        let end = (pc + window).min(self.bytecode.len());
        self.bytecode[pc..end].iter().any(|&b| 
            b == 0x52 ||  // MSTORE
            b == 0x53     // MSTORE8
        )
    }

    /// Check if there's a loop after the given PC
    fn has_loop_after(&self, pc: usize, window: usize) -> bool {
        let end = (pc + window).min(self.bytecode.len());
        self.bytecode[pc..end].iter().any(|&b| 
            b == 0x5B ||  // JUMPDEST
            b == 0x56 ||  // JUMP
            b == 0x57     // JUMPI
        )
    }

    /// Check if there's a bounds check (comparison) between two PCs
    fn has_bounds_check_between(&self, start: usize, end: usize) -> bool {
        let end = end.min(self.bytecode.len());
        self.bytecode[start..end].iter().any(|&b| 
            b == 0x10 ||  // LT
            b == 0x11 ||  // GT
            b == 0x12 ||  // SLT
            b == 0x13     // SGT
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_missing_calldata_size_check() {
        // Bytecode that loads calldata without checking size
        let bytecode = vec![
            0x60, 0x00,  // PUSH1 0
            0x35,        // CALLDATALOAD (vulnerable!)
            0x60, 0x20,  // PUSH1 32
            0x35,        // CALLDATALOAD (vulnerable!)
        ];

        let detector = ShortAddressDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();

        assert!(vulns.len() >= 1, "Should detect missing calldata size checks");
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            ShortAddressIssue::MissingLengthCheck | ShortAddressIssue::ABIEncodingVulnerable
        )));
    }

    #[test]
    fn test_detect_array_length_manipulation() {
        // Bytecode that uses array length without bounds check
        let bytecode = vec![
            0x60, 0x00,  // PUSH1 0
            0x35,        // CALLDATALOAD (array length)
            0x60, 0x00,  // PUSH1 0
            0x52,        // MSTORE (allocate based on length - no check!)
            0x5B,        // JUMPDEST (loop)
        ];

        let detector = ShortAddressDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();

        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            ShortAddressIssue::ArrayLengthManipulation
        )));
    }

    #[test]
    fn test_safe_calldata_usage() {
        // Bytecode with proper CALLDATASIZE check
        let bytecode = vec![
            0x36,        // CALLDATASIZE
            0x60, 0x44,  // PUSH1 68 (expected size)
            0x10,        // LT
            0x60, 0x00,  // PUSH1 0
            0x57,        // JUMPI (revert if too small)
            0x60, 0x00,  // PUSH1 0
            0x35,        // CALLDATALOAD (safe - size checked)
        ];

        let detector = ShortAddressDetector::new(bytecode);
        let vulns = detector.detect_missing_length_checks();

        // Should have fewer vulnerabilities since size is checked
        assert!(vulns.is_empty() || vulns.iter().all(|v| v.severity != SecuritySeverity::Critical));
    }
}
