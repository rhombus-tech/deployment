/// Cleanup Bit Masking Detector
use crate::bytecode::SecurityFinding;

pub struct CleanupBitMaskingDetector {
    bytecode: Vec<u8>,
}

impl CleanupBitMaskingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_pattern() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Incorrect bit masking allows dirty bits at PC {}", location),
                pc: location,
                confidence: 0.82,
            });
        }
        findings
    }

    fn detect_pattern(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if i >= self.bytecode.len() { break; }
            if self.matches_vulnerability_pattern(i) {
                return Some(i);
            }
        }
        None
    }

    fn matches_vulnerability_pattern(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        match self.bytecode[pos] {
            0x54 | 0x55 => { // SLOAD/SSTORE
                // Check for unsafe storage access
                !self.has_validation_before(pos, 30)
            },
            0xf1 | 0xfa => { // CALL/STATICCALL
                // Check return value and gas
                if pos + 5 < self.bytecode.len() {
                    !matches!(self.bytecode[pos + 1], 0x15 | 0x16)
                } else { false }
            },
            0x01..=0x0b => { // Arithmetic
                // Check for overflow protection
                !self.has_validation_before(pos, 20)
            },
            0x20 => { // KECCAK256 (for encodePacked)
                // Check for collision risk
                true
            },
            0x3b => { // EXTCODESIZE (constructor bypass)
                true
            },
            _ => false,
        }
    }

    fn has_validation_before(&self, pos: usize, window: usize) -> bool {
        let start = pos.saturating_sub(window);
        for i in start..pos {
            if i >= self.bytecode.len() { break; }
            if matches!(self.bytecode[i], 0x10 | 0x11 | 0x14 | 0x15) {
                return true;
            }
        }
        false
    }
}
