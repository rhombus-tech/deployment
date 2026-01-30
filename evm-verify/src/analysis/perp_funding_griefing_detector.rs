/// Perpetual Funding Rate Griefing Detector
use crate::bytecode::SecurityFinding;

pub struct PerpFundingGriefingDetector {
    bytecode: Vec<u8>,
}

impl PerpFundingGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Perpetual funding rate griefing vulnerability at PC {}", location),
                pc: location,
                confidence: 0.90,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(70) {
            if self.check_funding_griefing(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_funding_griefing(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for funding rate calculation vulnerable to manipulation
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // getFundingRate, updateFunding, settleFunding selectors
            if matches!(self.bytecode[pos+1], 0x1f | 0x3e | 0x67 | 0x9b) {
                let mut uses_spot_skew = false;
                let mut has_funding_cap = false;
                let mut has_time_weighted_average = false;
                let mut has_position_size_limit = false;
                
                if pos + 65 < self.bytecode.len() {
                    // Check for spot skew calculation (long - short)
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x03 && j + 4 < self.bytecode.len() { // SUB
                            if self.bytecode[j + 2] == 0x04 { // DIV
                                uses_spot_skew = true;
                            }
                        }
                    }
                    
                    // Check for funding rate cap (GT/LT + MIN/MAX pattern)
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        if (self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11) && j + 6 < self.bytecode.len() {
                            // Check for conditional assignment (funding cap)
                            if self.bytecode[j + 3] == 0x57 || self.bytecode[j + 4] == 0x52 { // JUMPI/MSTORE
                                has_funding_cap = true;
                            }
                        }
                    }
                    
                    // Check for time-weighted averaging (multiple TIMESTAMP reads)
                    let mut timestamp_count = 0;
                    for j in (pos + 5)..(pos + 55).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 { // TIMESTAMP
                            timestamp_count += 1;
                        }
                    }
                    if timestamp_count >= 2 {
                        has_time_weighted_average = true;
                    }
                    
                    // Check for position size limits (GT check on position size)
                    for j in (pos + 5)..(pos + 65).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x11 && j + 3 < self.bytecode.len() { // GT
                            if matches!(self.bytecode[j + 2], 0x57 | 0xfd) { // REVERT
                                has_position_size_limit = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if uses spot skew without proper protections
                return uses_spot_skew && (!has_funding_cap || !has_time_weighted_average || !has_position_size_limit);
            }
        }
        false
    }
}
