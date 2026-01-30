/// Wormhole Bridge 2022 Exploit Detector
use crate::bytecode::SecurityFinding;

pub struct WormholeBridge2022Detector {
    bytecode: Vec<u8>,
}

impl WormholeBridge2022Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Wormhole-style signature verification bypass at PC {}", location),
                pc: location,
                confidence: 0.91,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.check_signature_verification(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_signature_verification(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for ecrecover without proper validation
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // ecrecover precompile address: 0x00000001
            if self.bytecode[pos+3] == 0x00 && self.bytecode[pos+4] == 0x01 {
                if pos + 40 < self.bytecode.len() {
                    let mut has_signature_check = false;
                    let mut validates_guardian_set = false;
                    
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        // Check for result validation
                        if self.bytecode[j] == 0x15 { // ISZERO (checking if ecrecover failed)
                            has_signature_check = true;
                        }
                        // Check for guardian set validation
                        if self.bytecode[j] == 0x54 { // SLOAD
                            validates_guardian_set = true;
                        }
                    }
                    
                    return !has_signature_check || !validates_guardian_set;
                }
            }
        }
        false
    }
}
