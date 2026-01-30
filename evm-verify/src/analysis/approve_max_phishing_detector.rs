use crate::bytecode::opcodes::*;

pub struct ApproveMaxPhishingDetector {
    bytecode: Vec<u8>,
}

impl ApproveMaxPhishingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_approve_max_pattern()
            && self.has_phishing_indicators()
            && !self.has_legitimate_use_case()
    }

    fn has_approve_max_pattern(&self) -> bool {
        // Look for approve(spender, type(uint256).max)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(40) {
            // PUSH4 for approve selector (0x095ea7b3)
            if self.bytecode[i] == PUSH4 && i + 4 < self.bytecode.len() {
                if self.bytecode[i+1] == 0x09 && self.bytecode[i+2] == 0x5e {
                    // Check for max uint256 value
                    if self.has_max_uint256_after(i + 5) {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_max_uint256_after(&self, start: usize) -> bool {
        for i in start..start.min(self.bytecode.len()).min(start + 35) {
            if self.bytecode[i] == PUSH32 {
                // Check if all following 32 bytes are 0xFF (max uint256)
                if i + 32 < self.bytecode.len() {
                    let all_ff = (i+1..i+33).all(|j| self.bytecode[j] == 0xFF);
                    if all_ff {
                        return true;
                    }
                }
            }
            // Also check for NOT(0) pattern
            if i + 2 < self.bytecode.len() {
                if self.bytecode[i] == PUSH1 && self.bytecode[i+1] == 0x00 && self.bytecode[i+2] == NOT {
                    return true;
                }
            }
        }
        false
    }

    fn has_phishing_indicators(&self) -> bool {
        // Multiple approves without checks
        self.has_multiple_approves_without_validation()
            || self.has_suspicious_transfer_after_approve()
    }

    fn has_multiple_approves_without_validation(&self) -> bool {
        let approve_count = self.count_approve_calls();
        approve_count >= 2 && !self.has_ownership_checks()
    }

    fn count_approve_calls(&self) -> usize {
        let mut count = 0;
        let mut i = 0;
        
        while i < self.bytecode.len().saturating_sub(4) {
            if self.bytecode[i] == PUSH4 && i + 4 < self.bytecode.len() {
                // approve selector 0x095ea7b3
                if self.bytecode[i+1] == 0x09 && self.bytecode[i+2] == 0x5e {
                    count += 1;
                }
            }
            i += 1;
        }
        count
    }

    fn has_ownership_checks(&self) -> bool {
        // Look for CALLER/ORIGIN checks before approve
        for &opcode in &self.bytecode {
            if opcode == CALLER || opcode == ORIGIN {
                return true;
            }
        }
        false
    }

    fn has_suspicious_transfer_after_approve(&self) -> bool {
        // Approve followed quickly by transferFrom
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(50) {
            if self.is_approve_selector(i) {
                // Check for transferFrom within 40 bytes
                for j in i+5..i.min(self.bytecode.len()).min(i+40) {
                    if self.is_transferfrom_selector(j) {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn is_approve_selector(&self, pos: usize) -> bool {
        pos + 4 < self.bytecode.len()
            && self.bytecode[pos] == PUSH4
            && self.bytecode[pos+1] == 0x09
            && self.bytecode[pos+2] == 0x5e
    }

    fn is_transferfrom_selector(&self, pos: usize) -> bool {
        pos + 4 < self.bytecode.len()
            && self.bytecode[pos] == PUSH4
            && self.bytecode[pos+1] == 0x23
            && self.bytecode[pos+2] == 0xb8
    }

    fn has_legitimate_use_case(&self) -> bool {
        // Legitimate contracts often have time locks or multi-sig
        self.has_timelock_pattern() || self.has_multisig_pattern()
    }

    fn has_timelock_pattern(&self) -> bool {
        self.bytecode.iter().any(|&op| op == TIMESTAMP) 
            && self.bytecode.windows(3).any(|w| w[0] == LT || w[0] == GT)
    }

    fn has_multisig_pattern(&self) -> bool {
        // Multiple CALLER checks = multi-sig
        self.bytecode.iter().filter(|&&op| op == CALLER).count() >= 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approve_max_phishing() {
        let bytecode = vec![
            PUSH4, 0x09, 0x5e, 0xa7, 0xb3, // approve selector
            PUSH1, 0x00, NOT,                // max uint256
            PUSH4, 0x23, 0xb8, 0x72, 0xdd, // transferFrom
            CALL,
        ];
        let detector = ApproveMaxPhishingDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_legitimate_approve() {
        let bytecode = vec![
            CALLER,                           // Ownership check
            PUSH4, 0x09, 0x5e, 0xa7, 0xb3,   // approve
            TIMESTAMP,                        // Timelock
            LT,
            CALL,
        ];
        let detector = ApproveMaxPhishingDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
