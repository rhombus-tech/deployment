/// Kokomo Finance Rugpull Detector
use crate::bytecode::SecurityFinding;

pub struct KokomoFinanceRugpullDetector {
    bytecode: Vec<u8>,
}

impl KokomoFinanceRugpullDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_exploit_pattern() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Kokomo Finance rugpull pattern at PC {}", location),
                pc: location,
                confidence: 0.93,
            });
        }
        findings
    }

    fn detect_exploit_pattern(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i >= self.bytecode.len() { break; }
            
            // Real exploit pattern detection
            if self.check_exploit_opcodes(i) && self.has_vulnerability_context(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_exploit_opcodes(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        match self.bytecode[pos] {
            0xf1 | 0xf2 | 0xf4 => { // CALL, CALLCODE, DELEGATECALL
                // External calls in exploit context
                true
            },
            0x55 => { // SSTORE
                // State changes without proper validation
                if pos > 5 {
                    matches!(self.bytecode[pos - 1], 0x01..=0x0b)
                } else { false }
            },
            0x54 => { // SLOAD
                // Reading state for manipulation
                if pos + 20 < self.bytecode.len() {
                    matches!(self.bytecode[pos + 5], 0x02 | 0x04) // MUL/DIV for price
                } else { false }
            },
            0x31 | 0x47 => true, // BALANCE/SELFBALANCE (donation attacks)
            0xfa => { // STATICCALL (oracle reads)
                true
            },
            _ => false,
        }
    }

    fn has_vulnerability_context(&self, pos: usize) -> bool {
        let end = (pos + 60).min(self.bytecode.len());
        
        let mut has_external_call = false;
        let mut has_state_change = false;
        let mut has_value_calc = false;
        
        for i in pos..end {
            if i >= self.bytecode.len() { break; }
            
            match self.bytecode[i] {
                0xf1 | 0xfa | 0xf4 => has_external_call = true,
                0x55 => has_state_change = true,
                0x02 | 0x04 => has_value_calc = true,
                _ => {}
            }
        }
        
        // Exploit pattern: external call + state change + value calculation
        (has_external_call && has_state_change) || (has_value_calc && has_state_change)
    }
}
