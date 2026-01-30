/// EOF Container Manipulation Detector
use crate::bytecode::SecurityFinding;

pub struct EofContainerManipulationDetector {
    bytecode: Vec<u8>,
}

impl EofContainerManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("EOF container manipulation vulnerability at PC {}", location),
                pc: location,
                confidence: 0.85,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        // Check if this is an EOF formatted contract
        if !self.is_eof_contract() {
            return None;
        }
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.check_eof_manipulation(i) {
                return Some(i);
            }
        }
        None
    }

    fn is_eof_contract(&self) -> bool {
        // EOF contracts start with magic bytes 0xEF00
        self.bytecode.len() >= 2 && self.bytecode[0] == 0xEF && self.bytecode[1] == 0x00
    }

    fn check_eof_manipulation(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for EOF-specific vulnerabilities
        
        // 1. Check for EXTCODECOPY on EOF contracts (not allowed)
        if self.bytecode[pos] == 0x3c { // EXTCODECOPY
            return true; // EOF contracts cannot use EXTCODECOPY
        }
        
        // 2. Check for dynamic jumps in EOF (only static jumps allowed)
        if self.bytecode[pos] == 0x56 { // JUMP (dynamic)
            // EOF only allows RJUMP/RJUMPI (relative jumps)
            return true;
        }
        
        // 3. Check for JUMPI (dynamic conditional jump)
        if self.bytecode[pos] == 0x57 { // JUMPI
            return true; // Should use RJUMPI in EOF
        }
        
        // 4. Check for code section boundary violations
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // Check if function selector leads to invalid section
            // EOF has explicit code sections that must be respected
            let selector = u32::from_be_bytes([
                self.bytecode[pos + 1],
                self.bytecode[pos + 2],
                self.bytecode[pos + 3],
                self.bytecode[pos + 4],
            ]);
            
            // Critical selectors that might manipulate sections
            if matches!(selector >> 24, 0xe0 | 0xe1 | 0xe2 | 0xe3) {
                // These are near EOF section markers
                return true;
            }
        }
        
        // 5. Check for DELEGATECALL to non-EOF contracts
        if self.bytecode[pos] == 0xf4 { // DELEGATECALL
            let mut validates_eof_target = false;
            
            // Check if code validates target is EOF before DELEGATECALL
            let start = pos.saturating_sub(30);
            if pos > 0 && start < self.bytecode.len() {
                for j in start..pos {
                    // Look for EXTCODEHASH check (should verify EF00 prefix)
                    if self.bytecode[j] == 0x3f { // EXTCODEHASH
                        validates_eof_target = true;
                    }
                }
            }
            
            // Vulnerable if DELEGATECALL without EOF validation
            return !validates_eof_target;
        }
        
        // 6. Check for CREATE/CREATE2 from EOF (has restrictions)
        if self.bytecode[pos] == 0xf0 || self.bytecode[pos] == 0xf5 { // CREATE/CREATE2
            let mut deploys_eof = false;
            
            // Check if CREATE deploys EOF format
            if pos + 20 < self.bytecode.len() {
                for j in (pos + 1)..(pos + 20).min(self.bytecode.len()) {
                    // Look for EF00 in deployed code
                    if j + 1 < self.bytecode.len() && self.bytecode[j] == 0xEF && self.bytecode[j + 1] == 0x00 {
                        deploys_eof = true;
                    }
                }
            }
            
            // Vulnerable if deploys non-EOF from EOF contract
            return !deploys_eof;
        }
        
        false
    }
}
