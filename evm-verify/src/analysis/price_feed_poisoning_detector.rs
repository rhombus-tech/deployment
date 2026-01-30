/// Price Feed Poisoning Detector
use crate::bytecode::SecurityFinding;

pub struct PriceFeedPoisoningDetector {
    bytecode: Vec<u8>,
}

impl PriceFeedPoisoningDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Price feed poisoning vulnerability at PC {}", location),
                pc: location,
                confidence: 0.89,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.check_feed_poisoning(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_feed_poisoning(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for oracle address that can be changed without timelock
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // setOracle, updateOracle selectors
            if matches!(self.bytecode[pos+1], 0x7a | 0xb5) {
                let mut has_timelock = false;
                let mut has_multi_sig = false;
                
                if pos + 45 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        // TIMESTAMP check for timelock
                        if self.bytecode[j] == 0x42 && j + 10 < self.bytecode.len() {
                            // ADD for timestamp + delay, then GT comparison
                            if self.bytecode[j + 3] == 0x01 && matches!(self.bytecode[j + 6], 0x10 | 0x11) {
                                has_timelock = true;
                            }
                        }
                        
                        // Multiple CALLER checks for multi-sig
                        let mut caller_count = 0;
                        for k in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x33 { caller_count += 1; }
                        }
                        if caller_count >= 3 { has_multi_sig = true; }
                    }
                }
                return !has_timelock && !has_multi_sig;
            }
        }
        false
    }
}
