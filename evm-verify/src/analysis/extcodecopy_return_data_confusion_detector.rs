use crate::bytecode::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtcodecopyConfusionVulnerability {
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

/// EXTCODECOPY Return Data Confusion Detector
///
/// Detects vulnerabilities where EXTCODECOPY is confused with RETURNDATACOPY, or where
/// code copying operations have unexpected behavior leading to security issues.
///
/// Confusion Vectors:
/// - EXTCODECOPY gets deployed code, RETURNDATACOPY gets call return data
/// - EXTCODECOPY during constructor returns init code, not runtime code
/// - EXTCODESIZE returns 0 for contracts in construction
/// - Return data is cleared between external calls
/// - EXTCODECOPY can copy from self-destructed contracts
///
/// Security Implications:
/// - Incorrect bytecode validation using wrong opcode
/// - Proxy implementations incorrectly verified
/// - Factory pattern bugs with constructor vs runtime code
/// - Return data persistence assumptions leading to exploits
///
/// Real-World Cases:
/// - Proxy verification bypassed due to init code vs runtime confusion
/// - Factory contracts deploying wrong bytecode
/// - Bytecode verification systems fooled by timing
/// - Cross-contract code copying vulnerabilities
///
/// Detection Strategy:
/// - Identifies EXTCODECOPY used for return data verification
/// - Detects confusion between EXTCODESIZE and RETURNDATASIZE
/// - Looks for code copying without proper validation
/// - Checks for timing-dependent code copy operations
/// - Identifies unsafe bytecode verification patterns
pub struct ExtcodecopyReturnDataConfusionDetector {
    bytecode: Vec<u8>,
}

impl ExtcodecopyReturnDataConfusionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self, bytecode: &[u8]) -> Vec<ExtcodecopyConfusionVulnerability> {
        self.detect(&self.bytecode)
            .into_iter()
            .map(|finding| ExtcodecopyConfusionVulnerability {
                location: finding.pc,
                severity: format!("{:?}", finding.severity),
                description: finding.description,
                confidence: finding.confidence as f32,
            })
            .collect()
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: EXTCODECOPY after external call (likely should be RETURNDATACOPY)
            if bytecode[i] == 0x3c {
                if self.has_extcodecopy_after_call(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "EXTCODECOPY/RETURNDATACOPY confusion: Using EXTCODECOPY to retrieve call results, should use RETURNDATACOPY".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            // Pattern 2: EXTCODESIZE for return data validation (wrong opcode)
            if bytecode[i] == 0x3b {
                if self.has_extcodesize_for_return_data(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "EXTCODESIZE misuse: Using EXTCODESIZE instead of RETURNDATASIZE for return data validation".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            // Pattern 3: EXTCODECOPY during CREATE/CREATE2 (init code vs runtime)
            if bytecode[i] == 0x3c {
                if self.has_extcodecopy_during_creation(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "EXTCODECOPY timing issue: Copying code during contract creation may get init code instead of runtime code".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            // Pattern 4: Multiple EXTCODECOPY without size validation
            if bytecode[i] == 0x3c {
                if self.has_unsafe_extcodecopy_pattern(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Unsafe EXTCODECOPY: Code copying without proper size validation can lead to memory corruption".to_string(),
                        pc: i,
                        confidence: 0.83,
                    });
                }
            }

            // Pattern 5: RETURNDATACOPY size confusion
            if bytecode[i] == 0x3e {
                if self.has_returndatacopy_size_confusion(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "RETURNDATACOPY size confusion: Return data size assumptions without RETURNDATASIZE check enable exploits".to_string(),
                        pc: i,
                        confidence: 0.85,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    fn has_extcodecopy_after_call(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let mut has_call = false;
        let mut has_returndatacopy = false;
        let mut call_success_check = false;

        // Check for external call before EXTCODECOPY
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0xf1 | 0xfa | 0xf4 => has_call = true, // CALL, STATICCALL, DELEGATECALL
                    0x3e => has_returndatacopy = true, // RETURNDATACOPY (correct)
                    0x15 => {
                        // ISZERO (checking call success)
                        if has_call {
                            call_success_check = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // EXTCODECOPY after call without RETURNDATACOPY suggests confusion
        has_call && call_success_check && !has_returndatacopy
    }

    fn has_extcodesize_for_return_data(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 20.min(pos);
        let window = 15.min(bytecode.len().saturating_sub(pos));
        
        let mut has_call_before = false;
        let mut has_comparison = false;
        let mut no_returndatasize = true;

        // Check for call before EXTCODESIZE
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0xf1 | 0xfa => has_call_before = true, // CALL, STATICCALL
                    0x3d => no_returndatasize = false, // RETURNDATASIZE (correct opcode)
                    _ => {}
                }
            }
        }

        // Check for comparison after EXTCODESIZE
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if matches!(bytecode[pos + offset], 0x14 | 0x10 | 0x11) {
                    has_comparison = true;
                    break;
                }
            }
        }

        // EXTCODESIZE used for size check after call
        has_call_before && has_comparison && no_returndatasize
    }

    fn has_extcodecopy_during_creation(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let mut has_create = false;
        let mut has_address_check = false;
        let mut extcodesize_check = false;

        // Check for CREATE/CREATE2 before EXTCODECOPY
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0xf0 | 0xf5 => has_create = true, // CREATE, CREATE2
                    0x3b => extcodesize_check = true, // EXTCODESIZE
                    0x15 => {
                        // ISZERO (checking if address is contract)
                        if extcodesize_check {
                            has_address_check = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // EXTCODECOPY after CREATE without waiting for construction
        has_create && has_address_check
    }

    fn has_unsafe_extcodecopy_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 25.min(pos);
        let mut has_extcodesize = false;
        let mut has_size_validation = false;
        let mut has_memory_allocation = false;

        // Check for proper size validation before EXTCODECOPY
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x3b => has_extcodesize = true, // EXTCODESIZE
                    0x10 | 0x11 => {
                        // LT, GT (size validation)
                        if has_extcodesize {
                            has_size_validation = true;
                        }
                    }
                    0x40 => has_memory_allocation = true, // MLOAD(0x40) - free memory pointer
                    _ => {}
                }
            }
        }

        // EXTCODECOPY without proper validation
        !has_size_validation || (!has_memory_allocation && has_extcodesize)
    }

    fn has_returndatacopy_size_confusion(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 20.min(pos);
        let mut has_returndatasize = false;
        let mut has_hardcoded_size = false;
        let mut has_call = false;

        // Check for size source before RETURNDATACOPY
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x3d => has_returndatasize = true, // RETURNDATASIZE (safe)
                    0x60..=0x7f => {
                        // PUSH (hardcoded size - dangerous)
                        if !has_returndatasize {
                            has_hardcoded_size = true;
                        }
                    }
                    0xf1 | 0xfa | 0xf4 => has_call = true, // External call
                    _ => {}
                }
            }
        }

        // RETURNDATACOPY with hardcoded size instead of RETURNDATASIZE
        has_call && has_hardcoded_size && !has_returndatasize
    }
}
