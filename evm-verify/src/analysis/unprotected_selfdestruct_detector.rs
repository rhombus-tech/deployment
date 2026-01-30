/// Unprotected Selfdestruct Detector
use crate::bytecode::SecurityFinding;

pub struct UnprotectedSelfdestructDetector {
    bytecode: Vec<u8>,
}

impl UnprotectedSelfdestructDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Unprotected selfdestruct enables contract destruction at PC {}", location),
                pc: location,
                confidence: 0.93,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if i >= self.bytecode.len() { break; }
            if self.check_vulnerability_pattern(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_vulnerability_pattern(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        match self.bytecode[pos] {
            0x33 => { // CALLER
                // Check for access control
                if pos + 30 < self.bytecode.len() {
                    let mut has_check = false;
                    for j in (pos + 1)..(pos + 30).min(self.bytecode.len()) {
                        if j >= self.bytecode.len() { break; }
                        if matches!(self.bytecode[j], 0x14 | 0x10 | 0x11) {
                            has_check = true;
                            break;
                        }
                    }
                    !has_check
                } else {
                    false
                }
            },
            0xf4 => { // DELEGATECALL
                // Check for delegatecall safety
                if pos > 10 {
                    for j in pos.saturating_sub(10)..pos {
                        if j >= self.bytecode.len() { break; }
                        if self.bytecode[j] == 0x35 { // CALLDATALOAD (user input)
                            return true;
                        }
                    }
                }
                false
            },
            0xff => { // SELFDESTRUCT
                // Check for protection
                if pos > 20 {
                    let mut has_protection = false;
                    for j in pos.saturating_sub(20)..pos {
                        if j >= self.bytecode.len() { break; }
                        if self.bytecode[j] == 0x33 { // CALLER check
                            has_protection = true;
                            break;
                        }
                    }
                    !has_protection
                } else {
                    true
                }
            },
            0x54 | 0x55 => { // SLOAD/SSTORE
                // Storage operations
                if pos + 40 < self.bytecode.len() {
                    self.check_storage_safety(pos)
                } else {
                    false
                }
            },
            0xfa => { // STATICCALL (oracle read)
                // Oracle manipulation check
                if pos + 30 < self.bytecode.len() {
                    self.check_oracle_safety(pos)
                } else {
                    false
                }
            },
            0x63 => { // PUSH4 (selector)
                // Function selector check
                if pos + 4 < self.bytecode.len() {
                    self.check_selector_collision(pos)
                } else {
                    false
                }
            },
            _ => false,
        }
    }

    fn check_storage_safety(&self, pos: usize) -> bool {
        let end = (pos + 40).min(self.bytecode.len());
        let mut unsafe_pattern = false;
        
        for i in pos..end {
            if i >= self.bytecode.len() { break; }
            if matches!(self.bytecode[i], 0x01 | 0x02) { // ADD/MUL
                unsafe_pattern = true;
            }
        }
        
        unsafe_pattern
    }

    fn check_oracle_safety(&self, pos: usize) -> bool {
        let end = (pos + 30).min(self.bytecode.len());
        
        for i in (pos + 1)..end {
            if i >= self.bytecode.len() { break; }
            // Look for timestamp dependency
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                return true;
            }
        }
        false
    }

    fn check_selector_collision(&self, pos: usize) -> bool {
        if pos + 4 >= self.bytecode.len() { return false; }
        
        // Basic collision detection
        let selector = &self.bytecode[pos..pos+4];
        
        // Count occurrences of same selector
        let mut count = 0;
        for i in 0..self.bytecode.len().saturating_sub(4) {
            if i >= self.bytecode.len() { break; }
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                if &self.bytecode[i+1..i+5] == selector {
                    count += 1;
                }
            }
        }
        
        count > 1
    }
}
