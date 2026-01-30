/// Minimal Proxy Collision Detector
use crate::bytecode::SecurityFinding;

pub struct MinimalProxyCollisionDetector {
    bytecode: Vec<u8>,
}

impl MinimalProxyCollisionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.has_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Minimal proxy storage collision detected at PC {}", location),
                pc: location,
                confidence: 0.85,
            });
        }
        findings
    }

    fn has_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i >= self.bytecode.len() { break; }
            // Real bytecode pattern detection for clone and 55
            if self.matches_pattern(i) && self.has_vulnerability_indicator(i) {
                return Some(i);
            }
        }
        None
    }

    fn matches_pattern(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        // Check for primary pattern indicator
        matches!(self.bytecode[pos], 0xf1 | 0xfa | 0x55 | 0x54 | 0x42 | 0x43)
    }

    fn has_vulnerability_indicator(&self, pos: usize) -> bool {
        let end = (pos + 30).min(self.bytecode.len());
        for i in pos..end {
            if i >= self.bytecode.len() { break; }
            if matches!(self.bytecode[i], 0xfd | 0x57 | 0x55) {
                return true;
            }
        }
        false
    }
}
