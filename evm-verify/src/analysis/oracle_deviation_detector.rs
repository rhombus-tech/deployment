/// Oracle Deviation Attack Detector
use crate::bytecode::SecurityFinding;

pub struct OracleDeviationDetector {
    bytecode: Vec<u8>,
}

impl OracleDeviationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Oracle price deviation vulnerability at PC {}", location),
                pc: location,
                confidence: 0.85,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.check_deviation_vulnerability(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_deviation_vulnerability(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for oracle price usage without deviation check
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // latestAnswer, latestRoundData selectors
            if matches!(self.bytecode[pos+1], 0x50 | 0xfe | 0x9a) {
                let mut has_price_read = false;
                let mut has_deviation_check = false;
                
                if pos + 45 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        // STATICCALL to get price
                        if self.bytecode[j] == 0xfa { has_price_read = true; }
                        
                        // Look for deviation check (SUB + abs + GT comparison with threshold)
                        if has_price_read && self.bytecode[j] == 0x03 { // SUB
                            if j + 10 < self.bytecode.len() {
                                for k in (j+1)..(j+10).min(self.bytecode.len()) {
                                    // GT with threshold
                                    if self.bytecode[k] == 0x11 && k + 3 < self.bytecode.len() {
                                        if matches!(self.bytecode[k + 2], 0x57 | 0xfd) {
                                            has_deviation_check = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                return has_price_read && !has_deviation_check;
            }
        }
        false
    }
}
