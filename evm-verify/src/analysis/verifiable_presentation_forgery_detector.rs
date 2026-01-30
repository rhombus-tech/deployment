use crate::bytecode::SecurityFinding;

pub struct VerifiablePresentationForgeryDetector {
    bytecode: Vec<u8>,
}

impl VerifiablePresentationForgeryDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_missing_signature_verification() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Verifiable presentation accepted without signature verification at PC {}. \
                    Attackers can forge presentations and claim false credentials.",
                    pc
                ),
                pc,
                confidence: 0.94,
            });
        }

        if let Some(pc) = self.detect_challenge_reuse() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Presentation challenge can be reused, enabling replay attacks at PC {}. \
                    Missing nonce or timestamp validation.",
                    pc
                ),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_issuer_verification_bypass() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Credential issuer verification can be bypassed at PC {}. \
                    Presentations from untrusted issuers may be accepted.",
                    pc
                ),
                pc,
                confidence: 0.92,
            });
        }

        findings
    }

    fn detect_missing_signature_verification(&self) -> Option<usize> {
        // Look for verifyPresentation functions without ecrecover/signature checks
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // verifyPresentation, verifyVP, verifyCredential selectors
                if matches!(selector, [0x8f, 0x3a, _, _] | [0xa4, 0x5e, _, _] | [0xb7, 0x91, _, _]) {
                    let mut has_ecrecover = false;
                    let mut has_signature_check = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check for ecrecover precompile call
                        if j + 2 < self.bytecode.len() {
                            if self.bytecode[j] == 0x60 && self.bytecode[j + 1] == 0x01 {
                                // PUSH1 0x01 (ecrecover address)
                                if j + 10 < self.bytecode.len() {
                                    for k in j..j + 10 {
                                        if self.bytecode[k] == 0xf1 || self.bytecode[k] == 0xfa { // CALL or STATICCALL
                                            has_ecrecover = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        // Check for external signature verification contract call
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // verifySignature, checkSignature selectors
                            if matches!(sub_selector, [0xc1, 0x9d, _, _] | [0xd5, 0x4b, _, _]) {
                                has_signature_check = true;
                            }
                        }
                    }
                    
                    if !has_ecrecover && !has_signature_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_challenge_reuse(&self) -> Option<usize> {
        // Look for presentation verification without nonce/challenge validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // verifyPresentation, verifyVP selectors
                if matches!(selector, [0x8f, 0x3a, _, _] | [0xa4, 0x5e, _, _]) {
                    let mut has_nonce_check = false;
                    let mut has_timestamp_check = false;
                    let mut has_challenge_storage = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Check for nonce verification (SLOAD of nonce, comparison, SSTORE increment)
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 { // SLOAD
                                for k in j..j + 8 {
                                    if self.bytecode[k] == 0x14 { // EQ (comparing nonce)
                                        has_nonce_check = true;
                                    }
                                    if self.bytecode[k] == 0x55 { // SSTORE (storing used nonce)
                                        has_challenge_storage = true;
                                    }
                                }
                            }
                        }
                        // Check for timestamp validation
                        if j + 3 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 { // TIMESTAMP
                                if self.bytecode[j + 2] == 0x10 || self.bytecode[j + 2] == 0x11 { // LT or GT
                                    has_timestamp_check = true;
                                }
                            }
                        }
                    }
                    
                    if !has_nonce_check && !has_timestamp_check && !has_challenge_storage {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_issuer_verification_bypass(&self) -> Option<usize> {
        // Look for credential verification without issuer whitelist check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // verifyCredential, verifyPresentation selectors
                if matches!(selector, [0xb7, 0x91, _, _] | [0x8f, 0x3a, _, _]) {
                    let mut has_issuer_check = false;
                    let mut has_registry_lookup = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for issuer whitelist verification (SLOAD of trusted issuers mapping)
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 { // SLOAD
                                // Check if followed by comparison (EQ or ISZERO+ISZERO pattern)
                                for k in j..j + 6 {
                                    if self.bytecode[k] == 0x14 || // EQ
                                       (self.bytecode[k] == 0x15 && k + 1 < self.bytecode.len() && self.bytecode[k + 1] == 0x15) {
                                        has_issuer_check = true;
                                    }
                                }
                            }
                        }
                        // Check for external registry call (e.g., DID registry)
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // isTrustedIssuer, isRegistered selectors
                            if matches!(sub_selector, [0xc3, 0x8f, _, _] | [0xd2, 0x4e, _, _]) {
                                has_registry_lookup = true;
                            }
                        }
                    }
                    
                    if !has_issuer_check && !has_registry_lookup {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
