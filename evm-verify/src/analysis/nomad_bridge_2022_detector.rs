/// Nomad Bridge 2022 Exploit Detector
use crate::bytecode::SecurityFinding;

pub struct NomadBridge2022Detector {
    bytecode: Vec<u8>,
}

impl NomadBridge2022Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Nomad-style replica validation bypass at PC {}", location),
                pc: location,
                confidence: 0.92,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.check_message_validation(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_message_validation(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for message hash validation with weak checks
        if self.bytecode[pos] == 0x14 { // EQ comparison
            if pos + 30 < self.bytecode.len() {
                let mut has_hash_check = false;
                let mut validates_root = false;
                
                for j in pos.saturating_sub(20)..pos {
                    if j >= self.bytecode.len() { break; }
                    // Look for KECCAK256 (message hash)
                    if self.bytecode[j] == 0x20 {
                        has_hash_check = true;
                    }
                }
                
                // Check if comparing against stored root
                for j in (pos + 1)..(pos + 20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 { // SLOAD
                        validates_root = true;
                        break;
                    }
                }
                
                // Vulnerable if hash check without proper root validation
                if has_hash_check && !validates_root {
                    return true;
                }
            }
        }
        false
    }
}
