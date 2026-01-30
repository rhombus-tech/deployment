use crate::bytecode::SecurityFinding;

pub struct CelerBridgeSgnDetector {
    bytecode: Vec<u8>,
}

impl CelerBridgeSgnDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_sgn_validator_bypass() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Celer SGN validator signature bypass at PC {}. \
                    Bridge operations can proceed without proper validator consensus verification.",
                    pc
                ),
                pc,
                confidence: 0.91,
            });
        }

        if let Some(pc) = self.detect_relay_message_replay() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Celer bridge relay message vulnerable to replay attacks at PC {}. \
                    Missing nonce or unique message ID validation.",
                    pc
                ),
                pc,
                confidence: 0.93,
            });
        }

        if let Some(pc) = self.detect_insufficient_threshold() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Celer SGN validator threshold too low or missing at PC {}. \
                    Bridge can be compromised with insufficient validator consensus.",
                    pc
                ),
                pc,
                confidence: 0.88,
            });
        }

        findings
    }

    fn detect_sgn_validator_bypass(&self) -> Option<usize> {
        // Look for Celer bridge relay functions without proper SGN validator checks
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // relay, executeMessage, executeMessageWithTransfer selectors
                if matches!(selector, [0x84, 0x6c, _, _] | [0x59, 0x8f, _, _] | [0xa2, 0x1d, _, _]) {
                    let mut has_signature_verification = false;
                    let mut has_validator_check = false;
                    let mut has_threshold_check = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check for ecrecover (signature verification)
                        if j + 2 < self.bytecode.len() {
                            if self.bytecode[j] == 0x60 && self.bytecode[j + 1] == 0x01 { // PUSH1 0x01
                                has_signature_verification = true;
                            }
                        }
                        // Check for validator registry lookup
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x14 { // EQ (checking validator status)
                                has_validator_check = true;
                            }
                        }
                        // Check for threshold comparison
                        if j + 4 < self.bytecode.len() {
                            if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT or GT
                                has_threshold_check = true;
                            }
                        }
                    }
                    
                    if !has_signature_verification || !has_validator_check || !has_threshold_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_relay_message_replay(&self) -> Option<usize> {
        // Look for message relay without nonce/uniqueness validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // executeMessage, relay selectors
                if matches!(selector, [0x84, 0x6c, _, _] | [0x59, 0x8f, _, _]) {
                    let mut has_nonce_check = false;
                    let mut has_message_id_storage = false;
                    let mut processes_message = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for nonce validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (loading nonce)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x14 { // EQ (checking nonce)
                                has_nonce_check = true;
                            }
                        }
                        // Check for message ID storage (preventing replay)
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x20 && // KECCAK256 (message ID)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x55 { // SSTORE (storing message ID)
                                has_message_id_storage = true;
                            }
                        }
                        // Check if actually executing message
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // executeCall, processMessage selectors
                            if matches!(sub_selector, [0xc1, 0x2e, _, _] | [0xd3, 0x4f, _, _]) {
                                processes_message = true;
                            }
                        }
                    }
                    
                    if processes_message && !has_nonce_check && !has_message_id_storage {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_insufficient_threshold(&self) -> Option<usize> {
        // Look for threshold checks with low or missing validator requirements
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // verifySignatures, checkQuorum selectors
                if matches!(selector, [0xa8, 0x3e, _, _] | [0xb9, 0x4f, _, _]) {
                    let mut has_threshold_constant = false;
                    let mut threshold_value = 0u8;
                    let mut compares_count = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Look for threshold constant
                        if j + 1 < self.bytecode.len() {
                            if self.bytecode[j] == 0x60 { // PUSH1
                                threshold_value = self.bytecode[j + 1];
                                has_threshold_constant = true;
                            }
                        }
                        // Check for comparison operation
                        if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT or GT
                            compares_count = true;
                        }
                    }
                    
                    // Flag if threshold is too low (< 2/3 of typical validator set)
                    if has_threshold_constant && threshold_value < 2 && compares_count {
                        return Some(i);
                    }
                    // Flag if no threshold check at all
                    if !compares_count {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
