/// Ronin Bridge 2022 Exploit Detector
use crate::bytecode::SecurityFinding;

pub struct RoninBridge2022Detector {
    bytecode: Vec<u8>,
}

impl RoninBridge2022Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Ronin-style multisig threshold bypass at PC {}", location),
                pc: location,
                confidence: 0.90,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.check_multisig_threshold(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_multisig_threshold(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for threshold comparison without proper validation
        if matches!(self.bytecode[pos], 0x10 | 0x11) { // LT, GT
            if pos + 20 < self.bytecode.len() {
                let mut has_signature_count = false;
                let mut validates_signers = false;
                
                for j in pos.saturating_sub(15)..pos {
                    if j >= self.bytecode.len() { break; }
                    // Check for counter/accumulator (ADD pattern)
                    if self.bytecode[j] == 0x01 {
                        has_signature_count = true;
                    }
                }
                
                // Check if individual signers are validated
                for j in (pos + 1)..(pos + 20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 { // SLOAD (checking signer mapping)
                        validates_signers = true;
                        break;
                    }
                }
                
                return has_signature_count && !validates_signers;
            }
        }
        false
    }
}
