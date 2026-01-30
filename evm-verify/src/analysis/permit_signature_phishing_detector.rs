use crate::bytecode::opcodes::*;

pub struct PermitSignaturePhishingDetector {
    bytecode: Vec<u8>,
}

impl PermitSignaturePhishingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_permit_function()
            && (self.has_signature_replay_risk() || self.has_phishing_pattern())
    }

    fn has_permit_function(&self) -> bool {
        // EIP-2612 permit selector: 0xd505accf
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(4) {
            if self.bytecode[i] == PUSH4 && i + 4 < self.bytecode.len() {
                if self.bytecode[i+1] == 0xd5 && self.bytecode[i+2] == 0x05 {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_signature_replay_risk(&self) -> bool {
        // Permit without proper nonce checking
        self.has_permit_function() && !self.has_nonce_validation()
    }

    fn has_nonce_validation(&self) -> bool {
        // Look for nonce storage reads/writes
        let mut has_sload = false;
        let mut has_sstore = false;
        let mut has_increment = false;

        for (i, &opcode) in self.bytecode.iter().enumerate() {
            if opcode == SLOAD {
                has_sload = true;
            }
            if opcode == SSTORE {
                has_sstore = true;
            }
            // Increment pattern: ADD 1
            if opcode == ADD && i > 0 {
                if i + 2 < self.bytecode.len() && self.bytecode[i-1] == PUSH1 {
                    has_increment = true;
                }
            }
        }

        has_sload && has_sstore && has_increment
    }

    fn has_phishing_pattern(&self) -> bool {
        self.has_unlimited_approval_in_permit()
            || self.has_missing_deadline_check()
            || self.has_missing_signature_validation()
    }

    fn has_unlimited_approval_in_permit(&self) -> bool {
        // Check for max uint256 value near permit
        let mut found_permit = false;
        let mut i = 0;

        while i < self.bytecode.len().saturating_sub(40) {
            if self.is_permit_selector(i) {
                found_permit = true;
                // Look for max value in next 35 bytes
                if self.has_max_value_after(i + 5, 35) {
                    return true;
                }
            }
            i += 1;
        }

        found_permit
    }

    fn has_missing_deadline_check(&self) -> bool {
        // Permit should check deadline vs block.timestamp
        self.has_permit_function() && !self.has_timestamp_comparison()
    }

    fn has_timestamp_comparison(&self) -> bool {
        let mut has_timestamp = false;
        let mut has_comparison = false;

        for (i, &opcode) in self.bytecode.iter().enumerate() {
            if opcode == TIMESTAMP {
                has_timestamp = true;
            }
            if (opcode == LT || opcode == GT) && has_timestamp {
                has_comparison = true;
            }
        }

        has_timestamp && has_comparison
    }

    fn has_missing_signature_validation(&self) -> bool {
        // Should have ECRECOVER for signature validation
        !self.bytecode.iter().any(|&op| op == STATICCALL || op == CALL)
            || !self.has_ecrecover_pattern()
    }

    fn has_ecrecover_pattern(&self) -> bool {
        // ECRECOVER precompile address is 0x01
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == PUSH1 && i + 1 < self.bytecode.len() {
                if self.bytecode[i+1] == 0x01 {
                    // Check for STATICCALL/CALL nearby
                    for j in i+2..i.min(self.bytecode.len()).min(i+8) {
                        if self.bytecode[j] == STATICCALL || self.bytecode[j] == CALL {
                            return true;
                        }
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn is_permit_selector(&self, pos: usize) -> bool {
        pos + 4 < self.bytecode.len()
            && self.bytecode[pos] == PUSH4
            && self.bytecode[pos+1] == 0xd5
            && self.bytecode[pos+2] == 0x05
    }

    fn has_max_value_after(&self, start: usize, range: usize) -> bool {
        for i in start..start.min(self.bytecode.len()).min(start + range) {
            if self.bytecode[i] == PUSH32 {
                if i + 32 < self.bytecode.len() {
                    let all_ff = (i+1..i+33).all(|j| self.bytecode.get(j) == Some(&0xFF));
                    if all_ff {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permit_phishing_detection() {
        let bytecode = vec![
            PUSH4, 0xd5, 0x05, 0xac, 0xcf, // permit selector
            PUSH32, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // max uint256
            CALL,
        ];
        let detector = PermitSignaturePhishingDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_safe_permit() {
        let bytecode = vec![
            PUSH4, 0xd5, 0x05, 0xac, 0xcf, // permit selector
            SLOAD,                          // Nonce check
            PUSH1, 0x01, ADD,               // Increment
            SSTORE,                         // Store nonce
            TIMESTAMP, LT,                  // Deadline check
            PUSH1, 0x01, STATICCALL,        // ECRECOVER
        ];
        let detector = PermitSignaturePhishingDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
