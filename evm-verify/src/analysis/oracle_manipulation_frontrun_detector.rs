/// Oracle Manipulation Frontrunning Detector
use crate::bytecode::SecurityFinding;

pub struct OracleManipulationFrontrunDetector {
    bytecode: Vec<u8>,
}

impl OracleManipulationFrontrunDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Oracle manipulation frontrunning vulnerability at PC {}", location),
                pc: location,
                confidence: 0.89,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.check_oracle_frontrun(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_oracle_frontrun(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for oracle price usage that can be frontrun via pool manipulation
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // getPrice, latestAnswer, getReserves selectors
            if matches!(self.bytecode[pos+1], 0x09 | 0x50 | 0x0c) {
                let mut has_twap = false;
                let mut has_multiple_sources = false;
                let mut oracle_call_count = 0;
                
                if pos + 55 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 55).min(self.bytecode.len()) {
                        // Check for time-weighted calculation (multiple timestamp SLOADs)
                        if self.bytecode[j] == 0x42 { // TIMESTAMP
                            if j + 10 < self.bytecode.len() {
                                for k in (j+1)..(j+10).min(self.bytecode.len()) {
                                    if self.bytecode[k] == 0x42 {
                                        has_twap = true;
                                        break;
                                    }
                                }
                            }
                        }
                        
                        // Count external oracle calls
                        if self.bytecode[j] == 0xfa { // STATICCALL
                            oracle_call_count += 1;
                        }
                    }
                    
                    if oracle_call_count >= 2 {
                        has_multiple_sources = true;
                    }
                }
                
                // Vulnerable if single source and no TWAP
                return !has_twap && !has_multiple_sources;
            }
        }
        false
    }
}
