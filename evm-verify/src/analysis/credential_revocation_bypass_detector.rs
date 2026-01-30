use crate::bytecode::SecurityFinding;

pub struct CredentialRevocationBypassDetector {
    bytecode: Vec<u8>,
}

impl CredentialRevocationBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_missing_revocation_check() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Credential verification missing revocation list check at PC {}. \
                    Revoked credentials can still be accepted, enabling unauthorized access.",
                    pc
                ),
                pc,
                confidence: 0.92,
            });
        }

        if let Some(pc) = self.detect_stale_revocation_registry() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Revocation registry not updated with recent revocations at PC {}. \
                    System may accept recently revoked credentials due to stale data.",
                    pc
                ),
                pc,
                confidence: 0.88,
            });
        }

        if let Some(pc) = self.detect_revocation_oracle_bypass() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Revocation check can be bypassed through oracle manipulation at PC {}. \
                    Attacker can present revoked credentials as valid.",
                    pc
                ),
                pc,
                confidence: 0.90,
            });
        }

        findings
    }

    fn detect_missing_revocation_check(&self) -> Option<usize> {
        // Look for credential verification without revocation list checks
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // verifyCredential, checkCredential, validateCredential selectors
                if matches!(selector, [0xe3, 0x4a, _, _] | [0xf4, 0x5b, _, _] | [0xa2, 0x6c, _, _]) {
                    let mut has_revocation_check = false;
                    let mut has_registry_lookup = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for revocation registry SLOAD
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 { // SLOAD
                                // Check if loading from revocation mapping
                                for k in j..j + 6 {
                                    if self.bytecode[k] == 0x15 { // ISZERO (checking if NOT revoked)
                                        has_revocation_check = true;
                                    }
                                }
                            }
                        }
                        // Check for external revocation registry call
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // isRevoked, checkRevocation selectors
                            if matches!(sub_selector, [0xb1, 0x2f, _, _] | [0xc3, 0x4d, _, _]) {
                                has_registry_lookup = true;
                            }
                        }
                    }
                    
                    if !has_revocation_check && !has_registry_lookup {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_stale_revocation_registry(&self) -> Option<usize> {
        // Look for revocation checks without timestamp validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // isRevoked, checkRevocationStatus selectors
                if matches!(selector, [0xb1, 0x2f, _, _] | [0xc3, 0x4d, _, _]) {
                    let mut checks_revocation = false;
                    let mut validates_freshness = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Check if loading revocation data
                        if self.bytecode[j] == 0x54 { // SLOAD
                            checks_revocation = true;
                        }
                        // Check for timestamp/freshness validation
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x54 && // SLOAD (last update time)
                               (self.bytecode[j + 4] == 0x10 || self.bytecode[j + 4] == 0x11) { // LT or GT
                                validates_freshness = true;
                            }
                        }
                    }
                    
                    if checks_revocation && !validates_freshness {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_revocation_oracle_bypass(&self) -> Option<usize> {
        // Look for revocation checks relying on single oracle without verification
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // getRevocationStatus, queryRevocation selectors
                if matches!(selector, [0xd2, 0x3e, _, _] | [0xe4, 0x5f, _, _]) {
                    let mut has_single_oracle = false;
                    let mut has_multiple_sources = false;
                    let mut has_signature_verification = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for single external call
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0xfa || self.bytecode[j] == 0xf1 { // STATICCALL or CALL
                                has_single_oracle = true;
                            }
                        }
                        // Check for multiple oracle queries
                        if j + 30 < self.bytecode.len() {
                            let mut call_count = 0;
                            for k in j..j + 30 {
                                if self.bytecode[k] == 0xfa || self.bytecode[k] == 0xf1 {
                                    call_count += 1;
                                }
                            }
                            if call_count >= 2 {
                                has_multiple_sources = true;
                            }
                        }
                        // Check for signature verification on revocation data
                        if j + 2 < self.bytecode.len() {
                            if self.bytecode[j] == 0x60 && self.bytecode[j + 1] == 0x01 { // PUSH1 0x01 (ecrecover)
                                has_signature_verification = true;
                            }
                        }
                    }
                    
                    if has_single_oracle && !has_multiple_sources && !has_signature_verification {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
