/// ZK Soundness Break Detector
use crate::bytecode::SecurityFinding;

pub struct ZkSoundnessBreakDetector {
    bytecode: Vec<u8>,
}

impl ZkSoundnessBreakDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("ZK soundness break vulnerability at PC {}", location),
                pc: location,
                confidence: 0.83,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.check_soundness_break(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_soundness_break(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for ZK proof verification without proper soundness checks
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // verify, verifyProof, checkProof selectors
            if matches!(self.bytecode[pos+1], 0x1e | 0x3f | 0x7c | 0xa9) {
                let mut has_public_input_check = false;
                let mut has_proof_element_validation = false;
                let mut has_pairing_check = false;
                let mut validates_proof_size = false;
                
                if pos + 55 < self.bytecode.len() {
                    // Check for public input validation
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        // Should validate public inputs are in valid range
                        if self.bytecode[j] == 0x11 && j + 3 < self.bytecode.len() { // GT
                            if matches!(self.bytecode[j + 2], 0x57 | 0xfd) {
                                has_public_input_check = true;
                            }
                        }
                    }
                    
                    // Check for proof element validation (checking against field modulus)
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x09 { // MOD (checking field membership)
                            has_proof_element_validation = true;
                        }
                    }
                    
                    // Check for pairing check (STATICCALL to precompile 0x08)
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { // STATICCALL
                            has_pairing_check = true;
                        }
                    }
                    
                    // Check for proof size validation
                    for j in (pos + 5)..(pos + 55).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x14 && j + 3 < self.bytecode.len() { // EQ
                            // Should check proof has exact expected size
                            if matches!(self.bytecode[j + 2], 0x57 | 0xfd) {
                                validates_proof_size = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if:
                // 1. Doesn't validate public inputs properly
                // 2. Doesn't check proof elements are in field
                // 3. Missing pairing check
                // 4. Doesn't validate proof structure/size
                return !has_public_input_check || !has_proof_element_validation || !has_pairing_check || !validates_proof_size;
            }
        }
        false
    }
}
