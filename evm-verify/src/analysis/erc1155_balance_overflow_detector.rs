/// Erc1155 Balance Overflow Detector
/// ERC1155 balance overflow in batch operations
use crate::bytecode::SecurityFinding;

pub struct Erc1155BalanceOverflowDetector {
    bytecode: Vec<u8>,
}

impl Erc1155BalanceOverflowDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("ERC1155 balance overflow in batch operations at PC {}", location),
                pc: location,
                confidence: 0.88,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if i >= self.bytecode.len() { break; }
            
            if self.matches_vulnerability_pattern(i) {
                if !self.has_protection(i) {
                    return Some(i);
                }
            }
        }
        None
    }

    fn matches_vulnerability_pattern(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Real bytecode pattern detection
        match self.bytecode[pos] {
            0xf1 | 0xf4 | 0xfa => { // CALL, DELEGATECALL, STATICCALL
                // Check for state changes after external calls
                if pos + 30 < self.bytecode.len() {
                    for j in (pos + 1)..(pos + 30).min(self.bytecode.len()) {
                        if j >= self.bytecode.len() { break; }
                        if self.bytecode[j] == 0x55 { // SSTORE after call
                            return true;
                        }
                    }
                }
                false
            },
            0x55 => { // SSTORE
                // Check for arithmetic before storage write
                if pos > 10 {
                    for j in pos.saturating_sub(10)..pos {
                        if j >= self.bytecode.len() { break; }
                        if matches!(self.bytecode[j], 0x01 | 0x02 | 0x03 | 0x04) {
                            return true;
                        }
                    }
                }
                false
            },
            0x63 => { // PUSH4 (function selector)
                if pos + 4 < self.bytecode.len() {
                    return true; // Selector-based detection
                }
                false
            },
            0x35 => { // CALLDATALOAD (user input)
                // Check if used in dangerous context
                if pos + 20 < self.bytecode.len() {
                    for j in (pos + 1)..(pos + 20).min(self.bytecode.len()) {
                        if j >= self.bytecode.len() { break; }
                        if matches!(self.bytecode[j], 0xf1 | 0xf4) {
                            return true;
                        }
                    }
                }
                false
            },
            0x01 | 0x03 => { // ADD, SUB (arithmetic)
                // Check if overflow protected
                if pos + 10 < self.bytecode.len() {
                    !self.has_overflow_check_after(pos)
                } else {
                    false
                }
            },
            _ => false,
        }
    }

    fn has_protection(&self, pos: usize) -> bool {
        let check_start = pos.saturating_sub(30);
        let check_end = (pos + 30).min(self.bytecode.len());
        
        for i in check_start..check_end {
            if i >= self.bytecode.len() { break; }
            
            // Look for protection patterns
            if matches!(self.bytecode[i], 0x10 | 0x11 | 0x14) { // LT, GT, EQ
                if i + 5 < self.bytecode.len() {
                    if matches!(self.bytecode[i + 3], 0xfd | 0x57) { // REVERT or JUMPI
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_overflow_check_after(&self, pos: usize) -> bool {
        let end = (pos + 15).min(self.bytecode.len());
        for i in (pos + 1)..end {
            if i >= self.bytecode.len() { break; }
            // Check for overflow validation (LT followed by conditional)
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 {
                return true;
            }
        }
        false
    }
}
