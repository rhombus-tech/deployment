/// PUSH0 Opcode Bug Detector
use crate::bytecode::SecurityFinding;

pub struct Push0OpcodeBugDetector {
    bytecode: Vec<u8>,
}

impl Push0OpcodeBugDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("PUSH0 opcode compatibility issue at PC {}", location),
                pc: location,
                confidence: 0.82,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.check_push0_issue(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_push0_issue(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for PUSH0 (0x5f) opcode
        if self.bytecode[pos] == 0x5f {
            let mut used_in_critical_operation = false;
            let mut no_version_check = true;
            
            // Check if PUSH0 is used in critical operations
            if pos + 15 < self.bytecode.len() {
                for j in (pos + 1)..(pos + 15).min(self.bytecode.len()) {
                    // PUSH0 followed by critical opcodes
                    match self.bytecode[j] {
                        0xf0 | 0xf1 | 0xf2 | 0xf4 | 0xfa => { // CREATE, CALL, CALLCODE, DELEGATECALL, STATICCALL
                            used_in_critical_operation = true;
                        }
                        0x55 => { // SSTORE with zero value
                            used_in_critical_operation = true;
                        }
                        _ => {}
                    }
                }
            }
            
            // Check if contract has version/chain compatibility checks
            let check_start = pos.saturating_sub(50);
            if pos >= 50 && check_start < self.bytecode.len() {
                for j in check_start..pos {
                    // Look for CHAINID or version checks
                    if self.bytecode[j] == 0x46 { // CHAINID
                        no_version_check = false;
                    }
                }
            }
            
            // Vulnerable if:
            // 1. Uses PUSH0 without version/compatibility checks
            // 2. PUSH0 in critical operations that might fail on older chains
            // 3. Contract deployed to multiple chains without checking PUSH0 support
            return used_in_critical_operation && no_version_check;
        }
        
        // Also check for patterns that should use PUSH0 but use PUSH1 0x00
        if pos + 1 < self.bytecode.len() && self.bytecode[pos] == 0x60 && self.bytecode[pos + 1] == 0x00 {
            // This is PUSH1 0x00, which is gas-inefficient vs PUSH0 on Shanghai+
            // Count how many times this pattern appears
            let mut push1_zero_count = 0;
            for i in 0..self.bytecode.len().saturating_sub(1) {
                if self.bytecode[i] == 0x60 && self.bytecode[i + 1] == 0x00 {
                    push1_zero_count += 1;
                }
            }
            
            // If there are many PUSH1 0x00, suggest PUSH0 optimization
            if push1_zero_count > 5 {
                // This is more of a gas optimization issue than a security bug
                return false; // Don't flag as security issue
            }
        }
        
        false
    }
}
