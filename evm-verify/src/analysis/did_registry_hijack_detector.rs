use crate::bytecode::SecurityFinding;

pub struct DidRegistryHijackDetector {
    bytecode: Vec<u8>,
}

impl DidRegistryHijackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_ownership_takeover() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "DID registry allows ownership takeover without proper authorization at PC {}. \
                    Attacker can claim control of existing identities.",
                    pc
                ),
                pc,
                confidence: 0.93,
            });
        }

        if let Some(pc) = self.detect_attribute_manipulation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "DID attributes can be modified without owner signature verification at PC {}. \
                    Identity information can be tampered with.",
                    pc
                ),
                pc,
                confidence: 0.88,
            });
        }

        if let Some(pc) = self.detect_recovery_key_abuse() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Recovery key mechanism can be abused to bypass owner authorization at PC {}. \
                    Recovery keys can be set without proper safeguards.",
                    pc
                ),
                pc,
                confidence: 0.90,
            });
        }

        findings
    }

    fn detect_ownership_takeover(&self) -> Option<usize> {
        // Look for DID ownership transfer without proper authorization checks
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // changeOwner, transferOwnership, setController selectors for DID
                if matches!(selector, [0xa6, 0xf9, _, _] | [0xf2, 0xfd, _, _] | [0x92, 0xea, _, _]) {
                    let mut has_owner_check = false;
                    let mut has_signature_verification = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Check for current owner verification (CALLER check against stored owner)
                        if j + 5 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (loading current owner)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x33 { // CALLER
                                if j + 4 < self.bytecode.len() && self.bytecode[j + 4] == 0x14 { // EQ
                                    has_owner_check = true;
                                }
                            }
                        }
                        // Check for ecrecover signature verification
                        if j + 2 < self.bytecode.len() && self.bytecode[j] == 0x60 && self.bytecode[j + 1] == 0x01 {
                            // PUSH1 0x01 (ecrecover precompile address)
                            has_signature_verification = true;
                        }
                    }
                    
                    if !has_owner_check && !has_signature_verification {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_attribute_manipulation(&self) -> Option<usize> {
        // Look for setAttribute functions without proper authorization
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // setAttribute, setDIDDocument, updateAttribute selectors
                if matches!(selector, [0x6f, 0x7b, _, _] | [0x8d, 0x4c, _, _] | [0xb4, 0x91, _, _]) {
                    let mut has_authorization = false;
                    let mut stores_attribute = false;
                    
                    for j in i..i.saturating_add(50).min(self.bytecode.len()) {
                        // Check for owner/controller authorization
                        if j + 4 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD
                               j + 2 < self.bytecode.len() && self.bytecode[j + 2] == 0x33 && // CALLER
                               j + 3 < self.bytecode.len() && self.bytecode[j + 3] == 0x14 { // EQ
                                has_authorization = true;
                            }
                        }
                        if self.bytecode[j] == 0x55 { // SSTORE
                            stores_attribute = true;
                        }
                    }
                    
                    if stores_attribute && !has_authorization {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_recovery_key_abuse(&self) -> Option<usize> {
        // Look for recovery key functions that can be exploited
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // setRecoveryKey, addDelegate, addRecovery selectors
                if matches!(selector, [0x5c, 0x19, _, _] | [0x7e, 0xf4, _, _] | [0x9a, 0xb2, _, _]) {
                    let mut has_timelock = false;
                    let mut has_multisig = false;
                    let mut sets_recovery = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Check for timelock (TIMESTAMP comparison)
                        if j + 3 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               (self.bytecode[j + 2] == 0x10 || self.bytecode[j + 2] == 0x11) { // LT or GT
                                has_timelock = true;
                            }
                        }
                        // Check for multisig pattern (multiple CALLER checks or threshold)
                        if j + 10 < self.bytecode.len() {
                            let mut caller_count = 0;
                            for k in j..j + 10 {
                                if self.bytecode[k] == 0x33 { // CALLER
                                    caller_count += 1;
                                }
                            }
                            if caller_count >= 2 {
                                has_multisig = true;
                            }
                        }
                        if self.bytecode[j] == 0x55 { // SSTORE (setting recovery key)
                            sets_recovery = true;
                        }
                    }
                    
                    if sets_recovery && !has_timelock && !has_multisig {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
