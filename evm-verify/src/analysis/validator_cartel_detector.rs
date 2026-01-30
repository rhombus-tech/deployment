/// Validator Cartel Detector
use crate::bytecode::SecurityFinding;

pub struct ValidatorCartelDetector {
    bytecode: Vec<u8>,
}

impl ValidatorCartelDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_pattern() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Validator cartel detection at PC {}", location),
                pc: location,
                confidence: 0.87,
            });
        }
        findings
    }

    fn detect_pattern(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if i >= self.bytecode.len() { break; }
            
            if self.matches_attack_pattern(i) && self.has_attack_context(i) {
                return Some(i);
            }
        }
        None
    }

    fn matches_attack_pattern(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        match self.bytecode[pos] {
            0xf1 | 0xfa => { // CALL, STATICCALL
                // Check for MEV-related patterns
                if pos + 40 < self.bytecode.len() {
                    self.check_mev_pattern(pos)
                } else {
                    false
                }
            },
            0x31 | 0x47 => { // BALANCE, SELFBALANCE
                // Donation/inflation attacks
                if pos + 30 < self.bytecode.len() {
                    self.check_balance_manipulation(pos)
                } else {
                    false
                }
            },
            0x54 => { // SLOAD
                // State-based attacks
                if pos + 40 < self.bytecode.len() {
                    self.check_state_manipulation(pos)
                } else {
                    false
                }
            },
            0x02 | 0x04 => { // MUL, DIV
                // Price/value manipulation
                if pos + 30 < self.bytecode.len() {
                    self.check_price_manipulation(pos)
                } else {
                    false
                }
            },
            0x42 | 0x43 => { // TIMESTAMP, NUMBER
                // MEV timing attacks
                true
            },
            _ => false,
        }
    }

    fn has_attack_context(&self, pos: usize) -> bool {
        let end = (pos + 60).min(self.bytecode.len());
        
        let mut has_external_call = false;
        let mut has_state_change = false;
        let mut has_value_transfer = false;
        
        for i in pos..end {
            if i >= self.bytecode.len() { break; }
            
            match self.bytecode[i] {
                0xf1 | 0xfa | 0xf4 => has_external_call = true,
                0x55 => has_state_change = true,
                0x00 if i > 0 && self.bytecode[i-1] == 0xf1 => has_value_transfer = true,
                _ => {}
            }
        }
        
        // Attack requires combination of patterns
        (has_external_call && has_state_change) || 
        (has_value_transfer && has_state_change)
    }

    fn check_mev_pattern(&self, pos: usize) -> bool {
        let end = (pos + 40).min(self.bytecode.len());
        
        for i in (pos + 1)..end {
            if i >= self.bytecode.len() { break; }
            // Look for timestamp/blocknumber dependency
            if matches!(self.bytecode[i], 0x42 | 0x43) {
                return true;
            }
        }
        false
    }

    fn check_balance_manipulation(&self, pos: usize) -> bool {
        let end = (pos + 30).min(self.bytecode.len());
        
        for i in (pos + 1)..end {
            if i >= self.bytecode.len() { break; }
            // Balance used in calculations
            if matches!(self.bytecode[i], 0x02 | 0x04) { // MUL or DIV
                return true;
            }
        }
        false
    }

    fn check_state_manipulation(&self, pos: usize) -> bool {
        let end = (pos + 40).min(self.bytecode.len());
        let mut read_count = 0;
        
        for i in pos..end {
            if i >= self.bytecode.len() { break; }
            if self.bytecode[i] == 0x54 {
                read_count += 1;
            }
        }
        
        read_count >= 2 // Multiple state reads suggest manipulation
    }

    fn check_price_manipulation(&self, pos: usize) -> bool {
        let end = (pos + 30).min(self.bytecode.len());
        
        for i in (pos + 1)..end {
            if i >= self.bytecode.len() { break; }
            // Price calc followed by state write
            if self.bytecode[i] == 0x55 {
                return true;
            }
        }
        false
    }
}
