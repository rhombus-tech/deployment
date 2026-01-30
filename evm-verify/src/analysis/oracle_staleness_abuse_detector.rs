/// Oracle Staleness Abuse Detector
use crate::bytecode::SecurityFinding;

pub struct OracleStalenessAbuseDetector {
    bytecode: Vec<u8>,
}

impl OracleStalenessAbuseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Oracle staleness abuse vulnerability at PC {}", location),
                pc: location,
                confidence: 0.87,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(65) {
            if self.check_staleness_abuse(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_staleness_abuse(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for oracle usage without staleness checks
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // getPrice, latestAnswer, latestRoundData selectors
            if matches!(self.bytecode[pos+1], 0x41 | 0x50 | 0x9a | 0xfe) {
                let mut checks_update_timestamp = false;
                let mut validates_max_staleness = false;
                let mut requires_minimum_freshness = false;
                let mut handles_stale_data = false;
                
                if pos + 60 < self.bytecode.len() {
                    // Check for timestamp validation after oracle call
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 && j + 6 < self.bytecode.len() { // TIMESTAMP
                            if self.bytecode[j + 3] == 0x03 { // SUB (calculating age)
                                checks_update_timestamp = true;
                            }
                        }
                    }
                    
                    // Check for maximum staleness threshold
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x11 && j + 3 < self.bytecode.len() { // GT
                            // Should check if data is too old
                            if matches!(self.bytecode[j + 2], 0x57 | 0xfd) { // JUMPI/REVERT
                                validates_max_staleness = true;
                            }
                        }
                    }
                    
                    // Check for minimum freshness requirement
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x10 && j + 3 < self.bytecode.len() { // LT
                            // Should require data within time window
                            requires_minimum_freshness = true;
                        }
                    }
                    
                    // Check for fallback when data is stale
                    for j in (pos + 5)..(pos + 60).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { // STATICCALL to backup oracle
                            handles_stale_data = true;
                        }
                    }
                }
                
                // Vulnerable if stale oracle data can be abused via:
                // 1. No timestamp checking
                // 2. No staleness threshold
                // 3. No freshness requirement
                // 4. No fallback for stale data
                return !checks_update_timestamp || !validates_max_staleness || !requires_minimum_freshness || !handles_stale_data;
            }
        }
        false
    }
}
