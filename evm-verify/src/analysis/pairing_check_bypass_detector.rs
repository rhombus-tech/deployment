/// Pairing Check Bypass Detector
use crate::bytecode::SecurityFinding;

pub struct PairingCheckBypassDetector {
    bytecode: Vec<u8>,
}

impl PairingCheckBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!("Pairing check bypass vulnerability at PC {}", location),
                pc: location,
                confidence: 0.86,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(65) {
            if self.check_pairing_bypass(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_pairing_bypass(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for pairing verification that can be bypassed
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // verifyPairing, checkBN256, verifyGroth16 selectors
            if matches!(self.bytecode[pos+1], 0x29 | 0x5c | 0x8e | 0xb1) {
                let mut has_return_value_check = false;
                let mut validates_precompile_success = false;
                let mut checks_point_validity = false;
                let mut prevents_zero_points = false;
                
                if pos + 60 < self.bytecode.len() {
                    // Check if validates pairing precompile return value
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { // STATICCALL to precompile 0x08
                            // Should check return value after STATICCALL
                            if j + 10 < self.bytecode.len() {
                                for k in (j + 1)..(j + 10).min(self.bytecode.len()) {
                                    if self.bytecode[k] == 0x15 { // ISZERO (checking success)
                                        validates_precompile_success = true;
                                    }
                                    if self.bytecode[k] == 0x51 { // MLOAD (checking result)
                                        has_return_value_check = true;
                                    }
                                }
                            }
                        }
                    }
                    
                    // Check for point validity (on curve check)
                    for j in (pos + 5)..(pos + 50).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x09 { // MOD (field arithmetic for curve check)
                            checks_point_validity = true;
                        }
                    }
                    
                    // Check for zero point prevention
                    for j in (pos + 5)..(pos + 60).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x15 && j + 3 < self.bytecode.len() { // ISZERO
                            // Should reject zero points
                            if matches!(self.bytecode[j + 2], 0x57 | 0xfd) {
                                prevents_zero_points = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if:
                // 1. Doesn't check pairing result properly
                // 2. Doesn't validate precompile succeeded
                // 3. Doesn't verify points are on curve
                // 4. Accepts zero/invalid points
                return !has_return_value_check || !validates_precompile_success || !checks_point_validity || !prevents_zero_points;
            }
        }
        false
    }
}
