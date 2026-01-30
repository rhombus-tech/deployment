/// Oracle Griefing DOS Detector
use crate::bytecode::SecurityFinding;

pub struct OracleGriefingDetector {
    bytecode: Vec<u8>,
}

impl OracleGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Oracle griefing DOS vulnerability at PC {}", location),
                pc: location,
                confidence: 0.82,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.check_oracle_griefing(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_oracle_griefing(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for oracle update functions without access control or rate limiting
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // updateAnswer, transmit, fulfill selectors
            if matches!(self.bytecode[pos+1], 0xb5 | 0xc9 | 0x4e) {
                let mut has_access_control = false;
                let mut has_rate_limit = false;
                
                if pos + 35 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 35).min(self.bytecode.len()) {
                        // CALLER check for access control
                        if self.bytecode[j] == 0x33 && j + 3 < self.bytecode.len() {
                            if self.bytecode[j + 2] == 0x14 { // EQ
                                has_access_control = true;
                            }
                        }
                        
                        // TIMESTAMP check for rate limiting
                        if self.bytecode[j] == 0x42 && j + 5 < self.bytecode.len() {
                            if matches!(self.bytecode[j + 3], 0x10 | 0x11) {
                                has_rate_limit = true;
                            }
                        }
                    }
                }
                return !has_access_control && !has_rate_limit;
            }
        }
        false
    }
}
