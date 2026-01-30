/// Layerzero Endpoint Detector
use crate::bytecode::SecurityFinding;

pub struct LayerzeroEndpointDetector {
    bytecode: Vec<u8>,
}

impl LayerzeroEndpointDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("LayerZero endpoint manipulation at PC {}", location),
                pc: location,
                confidence: 0.89,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
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
            0xf1 | 0xf4 | 0xfa => { // External calls
                self.check_call_context(pos)
            },
            0x54 => { // SLOAD
                self.check_state_read(pos)
            },
            0x55 => { // SSTORE  
                self.check_state_write(pos)
            },
            0x01 => { // ECRECOVER
                self.check_signature_validation(pos)
            },
            0x20 => { // KECCAK256
                self.check_hash_usage(pos)
            },
            _ => false,
        }
    }

    fn check_call_context(&self, pos: usize) -> bool {
        let end = (pos + 40).min(self.bytecode.len());
        let mut has_validation = false;
        
        for i in pos..end {
            if i >= self.bytecode.len() { break; }
            if matches!(self.bytecode[i], 0x10 | 0x11 | 0x14 | 0x15) {
                has_validation = true;
                break;
            }
        }
        
        !has_validation
    }

    fn check_state_read(&self, pos: usize) -> bool {
        if pos + 20 >= self.bytecode.len() { return false; }
        
        // Check for unsafe state usage
        for i in (pos + 1)..(pos + 20).min(self.bytecode.len()) {
            if i >= self.bytecode.len() { break; }
            if matches!(self.bytecode[i], 0x02 | 0x04) { // MUL or DIV
                return true;
            }
        }
        false
    }

    fn check_state_write(&self, pos: usize) -> bool {
        if pos < 10 { return false; }
        
        for i in pos.saturating_sub(10)..pos {
            if i >= self.bytecode.len() { break; }
            if matches!(self.bytecode[i], 0xf1 | 0xf4) {
                return true;
            }
        }
        false
    }

    fn check_signature_validation(&self, pos: usize) -> bool {
        let end = (pos + 30).min(self.bytecode.len());
        
        for i in pos..end {
            if i >= self.bytecode.len() { break; }
            if self.bytecode[i] == 0x14 { // EQ check
                return false; // Has validation
            }
        }
        true // No validation found
    }

    fn check_hash_usage(&self, pos: usize) -> bool {
        if pos + 10 >= self.bytecode.len() { return false; }
        
        // Check for hash collision risks
        for i in (pos + 1)..(pos + 10).min(self.bytecode.len()) {
            if i >= self.bytecode.len() { break; }
            if self.bytecode[i] == 0x14 { // EQ comparison
                return true;
            }
        }
        false
    }
}
