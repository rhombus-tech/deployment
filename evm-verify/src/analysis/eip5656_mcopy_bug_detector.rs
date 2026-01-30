/// EIP-5656 MCOPY Opcode Bug Detector
use crate::bytecode::SecurityFinding;

pub struct Eip5656McopyBugDetector {
    bytecode: Vec<u8>,
}

impl Eip5656McopyBugDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("EIP-5656 MCOPY opcode bug at PC {}", location),
                pc: location,
                confidence: 0.84,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.check_mcopy_bug(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_mcopy_bug(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for MCOPY (0x5e) opcode usage without proper validation
        if self.bytecode[pos] == 0x5e {
            let mut has_length_check = false;
            let mut has_overlap_check = false;
            let mut has_bounds_check = false;
            
            // Look backwards for validation
            let start = pos.saturating_sub(25);
            if pos > 0 && start < self.bytecode.len() {
                for j in start..pos {
                    // Check for length validation (GT/LT with revert)
                    if (self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11) && j + 3 < self.bytecode.len() {
                        if matches!(self.bytecode[j + 2], 0x57 | 0xfd) {
                            has_length_check = true;
                        }
                    }
                    
                    // Check for overlap detection (comparing src and dst)
                    if self.bytecode[j] == 0x14 && j + 8 < self.bytecode.len() { // EQ
                        // Should check if dst == src or dst in [src, src+len)
                        if self.bytecode[j + 4] == 0x11 { // GT
                            has_overlap_check = true;
                        }
                    }
                    
                    // Check for memory bounds validation (comparing with MSIZE)
                    if self.bytecode[j] == 0x59 { // MSIZE
                        has_bounds_check = true;
                    }
                }
            }
            
            // Vulnerable if MCOPY used without proper validation
            // MCOPY is safe for most uses but can have issues with:
            // 1. Overlapping memory regions (forward/backward copy)
            // 2. Out of bounds access
            // 3. Extremely large lengths causing gas issues
            return !has_length_check || !has_overlap_check || !has_bounds_check;
        }
        false
    }
}
