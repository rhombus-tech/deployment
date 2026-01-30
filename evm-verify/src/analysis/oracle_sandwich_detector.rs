/// Oracle Sandwich Attack Detector
use crate::bytecode::SecurityFinding;

pub struct OracleSandwichDetector {
    bytecode: Vec<u8>,
}

impl OracleSandwichDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Oracle sandwich attack vulnerability at PC {}", location),
                pc: location,
                confidence: 0.87,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.check_oracle_sandwich(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_oracle_sandwich(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for oracle update followed by trade without price validation
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // Oracle update selectors (updateAnswer, latestRoundData)
            if matches!(self.bytecode[pos+1], 0x50 | 0xfe) {
                // Check for immediate swap/trade after oracle update
                let mut has_oracle_read = false;
                let mut has_trade = false;
                
                if pos + 55 < self.bytecode.len() {
                    for j in (pos + 5)..(pos + 55).min(self.bytecode.len()) {
                        // STATICCALL to oracle (latestRoundData)
                        if self.bytecode[j] == 0xfa { has_oracle_read = true; }
                        // CALL to DEX swap
                        if self.bytecode[j] == 0xf1 && has_oracle_read { has_trade = true; break; }
                    }
                }
                
                // Vulnerable if trade happens without price change validation
                if has_trade {
                    let mut has_price_check = false;
                    for j in (pos + 5)..(pos + 55).min(self.bytecode.len()) {
                        // Look for price comparison (GT/LT)
                        if matches!(self.bytecode[j], 0x10 | 0x11) && j + 3 < self.bytecode.len() {
                            if matches!(self.bytecode[j + 2], 0x57 | 0xfd) {
                                has_price_check = true;
                                break;
                            }
                        }
                    }
                    return !has_price_check;
                }
            }
        }
        false
    }
}
