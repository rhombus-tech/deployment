/// Tokenized Security Compliance Bypass Detector
use crate::bytecode::SecurityFinding;

pub struct TokenizedSecurityComplianceBypassDetector {
    bytecode: Vec<u8>,
}

impl TokenizedSecurityComplianceBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Tokenized security compliance bypass at PC {}", location),
                pc: location,
                confidence: 0.90,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.check_compliance_bypass(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_compliance_bypass(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for compliance mechanisms that can be bypassed
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // transfer, transferFrom, mint, burn selectors
            if matches!(self.bytecode[pos+1], 0xa9 | 0x23 | 0x40 | 0x42) {
                let mut checks_accredited_investor = false;
                let mut validates_transfer_restrictions = false;
                let mut enforces_lockup_period = false;
                let mut verifies_jurisdiction = false;
                
                if pos + 75 < self.bytecode.len() {
                    // Check for accredited investor status
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j + 6 < self.bytecode.len() { // SLOAD
                            if self.bytecode[j + 3] == 0x14 { // EQ (checking status)
                                checks_accredited_investor = true;
                            }
                        }
                    }
                    
                    // Check for transfer restriction validation (Reg D, Reg S, etc.)
                    for j in (pos + 5)..(pos + 45).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xfa { // STATICCALL to compliance module
                            validates_transfer_restrictions = true;
                        }
                    }
                    
                    // Check for lockup period enforcement
                    for j in (pos + 5)..(pos + 60).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 && j + 8 < self.bytecode.len() { // TIMESTAMP
                            if self.bytecode[j + 4] == 0x10 { // LT (checking lockup end)
                                enforces_lockup_period = true;
                            }
                        }
                    }
                    
                    // Check for jurisdiction verification
                    for j in (pos + 5)..(pos + 75).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j + 8 < self.bytecode.len() { // SLOAD
                            // Should check allowed jurisdictions
                            if self.bytecode[j + 5] == 0x15 { // ISZERO (checking blocked jurisdiction)
                                verifies_jurisdiction = true;
                            }
                        }
                    }
                }
                
                // Vulnerable if compliance can be bypassed via:
                // 1. No accredited investor check
                // 2. Missing transfer restriction validation
                // 3. Lockup periods not enforced
                // 4. Jurisdiction not verified
                return !checks_accredited_investor || !validates_transfer_restrictions || !enforces_lockup_period || !verifies_jurisdiction;
            }
        }
        false
    }
}
