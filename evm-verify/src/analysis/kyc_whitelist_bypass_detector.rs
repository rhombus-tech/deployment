/// KYC Whitelist Bypass Detector
use crate::bytecode::SecurityFinding;

pub struct KycWhitelistBypassDetector {
    bytecode: Vec<u8>,
}

impl KycWhitelistBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("KYC whitelist bypass vulnerability at PC {}", location),
                pc: location,
                confidence: 0.88,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(75) {
            if self.check_kyc_bypass(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_kyc_bypass(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for KYC/whitelist mechanisms that can be bypassed
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // transfer, transferFrom, approve, mint selectors
            if matches!(self.bytecode[pos+1], 0xa9 | 0x23 | 0x09 | 0x40) {
                let mut validates_sender_kyc = false;
                let mut validates_recipient_kyc = false;
                let mut prevents_contract_intermediary = false;
                let mut checks_delegatecall_context = false;
                
                if pos + 70 < self.bytecode.len() {
                    // Check for sender KYC validation
                    for j in (pos + 5)..(pos + 30).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x33 && j + 8 < self.bytecode.len() { // CALLER
                            if self.bytecode[j + 3] == 0x54 { // SLOAD (checking whitelist)
                                validates_sender_kyc = true;
                            }
                        }
                    }
                    
                    // Check for recipient KYC validation
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 && j + 6 < self.bytecode.len() { // SLOAD
                            // Should check recipient address in whitelist
                            if self.bytecode[j + 3] == 0x15 { // ISZERO (checking if NOT whitelisted)
                                validates_recipient_kyc = true;
                            }
                        }
                    }
                    
                    // Check for contract intermediary prevention
                    for j in (pos + 5)..(pos + 55).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x3b { // EXTCODESIZE
                            // Should prevent contracts from bypassing KYC
                            prevents_contract_intermediary = true;
                        }
                    }
                    
                    // Check for delegatecall context validation
                    for j in (pos + 5)..(pos + 70).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x32 { // ORIGIN
                            // Should validate actual transaction origin
                            checks_delegatecall_context = true;
                        }
                    }
                }
                
                // Vulnerable if KYC can be bypassed via:
                // 1. Sender KYC not validated
                // 2. Recipient KYC not validated
                // 3. Contract intermediaries allowed
                // 4. Delegatecall context not checked
                return !validates_sender_kyc || !validates_recipient_kyc || !prevents_contract_intermediary || !checks_delegatecall_context;
            }
        }
        false
    }
}
