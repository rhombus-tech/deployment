/// Unprotected Initialize Detector
/// Detects proxy initialize functions without access control
/// Vulnerable pattern: Public initialize function allows anyone to take ownership

use crate::bytecode::SecurityFinding;

pub struct UnprotectedInitializeDetector {
    bytecode: Vec<u8>,
}

impl UnprotectedInitializeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(location) = self.has_unprotected_initialize() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Unprotected initialize function at PC {}. Proxy initialize without access control allows takeover",
                    location
                ),
                pc: location,
                confidence: 0.93,
            });
        }

        findings
    }

    fn has_unprotected_initialize(&self) -> Option<usize> {
        // Common initialize selectors: initialize() = 0x8129fc1c, init() = 0xe1c7392a
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // Check for initialize selectors
                if selector == 0x8129fc1c || selector == 0xe1c7392a || selector == 0x485cc955 {
                    // Check for missing access control (no msg.sender check)
                    let has_access_control = self.has_sender_check_after(i);
                    let has_initialized_flag = self.has_initialized_check_after(i);
                    
                    if !has_access_control && !has_initialized_flag {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_sender_check_after(&self, pos: usize) -> bool {
        let end = (pos + 100).min(self.bytecode.len());
        
        for i in pos..end {
            if i >= self.bytecode.len() { break; }
            // Look for CALLER (0x33) followed by comparison
            if self.bytecode[i] == 0x33 {
                for j in (i + 1)..(i + 15).min(self.bytecode.len()) {
                    if j >= self.bytecode.len() { break; }
                    if self.bytecode[j] == 0x14 { // EQ
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_initialized_check_after(&self, pos: usize) -> bool {
        let end = (pos + 150).min(self.bytecode.len());
        
        // Look for storage load (initialized flag) followed by ISZERO check
        for i in pos..end {
            if i >= self.bytecode.len() { break; }
            if self.bytecode[i] == 0x54 { // SLOAD
                for j in (i + 1)..(i + 10).min(self.bytecode.len()) {
                    if j >= self.bytecode.len() { break; }
                    if self.bytecode[j] == 0x15 { // ISZERO
                        return true;
                    }
                }
            }
        }
        false
    }
}
