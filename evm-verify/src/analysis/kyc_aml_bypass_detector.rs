/// KYC/AML Bypass Detector
///
/// Detects circumvention of identity verification and compliance checks.
/// Coverage: Securitize, Polymath, regulated tokens
/// Market: $8B+ RWA tokenization

use crate::bytecode::SecurityFinding;

pub struct KycAmlBypassDetector {
    bytecode: Vec<u8>,
}

impl KycAmlBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_kyc_check_bypass() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Transfer lacks KYC verification, regulatory bypass at PC {}", pc),
                pc,
                confidence: 0.93,
            });
        }

        if let Some(pc) = self.detect_whitelist_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!("Investor whitelist modifiable without timelock at PC {}", pc),
                pc,
                confidence: 0.88,
            });
        }

        findings
    }

    fn detect_kyc_check_bypass(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                // transfer, transferFrom selectors
                if matches!(self.bytecode[i+1], 0xa9 | 0x23) {
                    let mut has_kyc_check = false;

                    for j in i..i+45.min(self.bytecode.len()) {
                        // Look for external call to KYC registry
                        if self.bytecode[j] == 0xfa { // STATICCALL
                            // Check if followed by ISZERO (revert if not verified)
                            if j+3 < self.bytecode.len() && self.bytecode[j+2] == 0x15 { // ISZERO
                                if j+6 < self.bytecode.len() && self.bytecode[j+5] == 0x57 { // JUMPI (revert)
                                    has_kyc_check = true;
                                }
                            }
                        }
                    }

                    if !has_kyc_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_whitelist_manipulation(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                // addToWhitelist, updateInvestor selectors
                if matches!(self.bytecode[i+1], 0xe4 | 0xf5) {
                    let mut has_timelock = false;

                    for j in i..i+40.min(self.bytecode.len()) {
                        // Check for timestamp delay
                        if self.bytecode[j] == 0x42 && j+10 < self.bytecode.len() { // TIMESTAMP
                            if self.bytecode[j+8] == 0x01 { // ADD (delay)
                                if self.bytecode[j+11] == 0x10 { // LT (comparison)
                                    has_timelock = true;
                                }
                            }
                        }
                    }

                    if !has_timelock {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
