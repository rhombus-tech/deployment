/// Bridge Signature Threshold Manipulation Detector
use crate::bytecode::SecurityFinding;

pub struct BridgeSignatureThresholdDetector {
    bytecode: Vec<u8>,
}

impl BridgeSignatureThresholdDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Bridge signature threshold vulnerability at PC {}", location),
                pc: location,
                confidence: 0.87,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.check_threshold_vulnerability(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_threshold_vulnerability(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for threshold changes without timelock/multi-sig
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // setThreshold, updateThreshold selectors
            if matches!(self.bytecode[pos+1], 0x69 | 0x7d | 0xb5) {
                let mut has_timelock = false;
                let mut has_multi_approval = false;
                
                if pos + 45 < self.bytecode.len() {
                    // Check for timelock delay
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 && j + 8 < self.bytecode.len() {
                            if self.bytecode[j + 3] == 0x01 && matches!(self.bytecode[j + 6], 0x10 | 0x11) {
                                has_timelock = true;
                            }
                        }
                    }
                    
                    // Check for multiple signature requirements
                    let mut sig_check_count = 0;
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa && j > 3 { // STATICCALL
                            if self.bytecode[j-2] == 0x01 { // ECRECOVER
                                sig_check_count += 1;
                            }
                        }
                    }
                    if sig_check_count >= 2 { has_multi_approval = true; }
                }
                return !has_timelock && !has_multi_approval;
            }
        }
        false
    }
}
