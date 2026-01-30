/// ERC-4337 UserOp Replay Attack Detector
use crate::bytecode::SecurityFinding;

pub struct UserOpReplayDetector {
    bytecode: Vec<u8>,
}

impl UserOpReplayDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("UserOp replay attack vulnerability at PC {}", location),
                pc: location,
                confidence: 0.88,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.check_userop_replay(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_userop_replay(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for validateUserOp without nonce validation
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // validateUserOp selector: 0x3a871cdd
            if self.bytecode[pos+1] == 0x3a && self.bytecode[pos+2] == 0x87 {
                let mut has_nonce_check = false;
                let mut has_nonce_increment = false;
                
                if pos + 45 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        // SLOAD for nonce
                        if self.bytecode[j] == 0x54 && j + 8 < self.bytecode.len() {
                            // Followed by comparison
                            if matches!(self.bytecode[j + 3], 0x14) {
                                has_nonce_check = true;
                            }
                            // Followed by ADD and SSTORE (increment)
                            if self.bytecode[j + 3] == 0x01 && self.bytecode[j + 6] == 0x55 {
                                has_nonce_increment = true;
                            }
                        }
                    }
                }
                return !has_nonce_check || !has_nonce_increment;
            }
        }
        false
    }
}
