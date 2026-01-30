use crate::bytecode::opcodes::*;

pub struct FrontendInjectionAttackDetector {
    bytecode: Vec<u8>,
}

impl FrontendInjectionAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_dynamic_data_injection()
            && (self.has_unchecked_calldata() || self.has_address_injection_risk())
    }

    fn has_dynamic_data_injection(&self) -> bool {
        // Contract accepts and uses raw calldata without validation
        self.has_calldatacopy_without_validation()
            || self.has_delegatecall_with_calldata()
    }

    fn has_calldatacopy_without_validation(&self) -> bool {
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == CALLDATACOPY {
                // Check if there's validation before use
                if !self.has_validation_after(i) {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_validation_after(&self, copy_pos: usize) -> bool {
        // Look for comparison/bounds checking after CALLDATACOPY
        for i in copy_pos+1..copy_pos.min(self.bytecode.len()).min(copy_pos+15) {
            if matches!(self.bytecode[i], LT | GT | EQ | ISZERO) {
                return true;
            }
        }
        false
    }

    fn has_delegatecall_with_calldata(&self) -> bool {
        // DELEGATECALL using raw calldata (dangerous pattern)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == CALLDATASIZE || self.bytecode[i] == CALLDATACOPY {
                for j in i+1..i.min(self.bytecode.len()).min(i+15) {
                    if self.bytecode[j] == DELEGATECALL {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_unchecked_calldata(&self) -> bool {
        // Calldata used in critical operations without validation
        self.has_calldata_in_storage_ops() || self.has_calldata_in_calls()
    }

    fn has_calldata_in_storage_ops(&self) -> bool {
        // CALLDATALOAD followed by SSTORE without checks
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == CALLDATALOAD {
                let mut has_validation = false;
                let mut has_sstore = false;

                for j in i+1..i.min(self.bytecode.len()).min(i+12) {
                    if matches!(self.bytecode[j], LT | GT | EQ) {
                        has_validation = true;
                    }
                    if self.bytecode[j] == SSTORE {
                        has_sstore = true;
                    }
                }

                if has_sstore && !has_validation {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_calldata_in_calls(&self) -> bool {
        // CALLDATALOAD followed by CALL without validation
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == CALLDATALOAD {
                for j in i+1..i.min(self.bytecode.len()).min(i+12) {
                    if self.bytecode[j] == CALL || self.bytecode[j] == DELEGATECALL {
                        // Check if there was validation
                        if !self.has_validation_between(i, j) {
                            return true;
                        }
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_validation_between(&self, start: usize, end: usize) -> bool {
        for i in start..end.min(self.bytecode.len()) {
            if matches!(self.bytecode[i], LT | GT | EQ | ISZERO | REVERT) {
                return true;
            }
        }
        false
    }

    fn has_address_injection_risk(&self) -> bool {
        // Address parameters used without validation
        self.has_unchecked_address_param() || self.has_recipient_injection()
    }

    fn has_unchecked_address_param(&self) -> bool {
        // CALLDATALOAD with address extraction but no validation
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == CALLDATALOAD {
                // Check for address masking (AND with 0xff...ff)
                let mut has_and = false;
                let mut has_validation = false;

                for j in i+1..i.min(self.bytecode.len()).min(i+15) {
                    if self.bytecode[j] == AND {
                        has_and = true;
                    }
                    if matches!(self.bytecode[j], EQ | ISZERO) {
                        has_validation = true;
                    }
                }

                if has_and && !has_validation {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_recipient_injection(&self) -> bool {
        // Transfer to unchecked calldata address
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(30) {
            if self.is_transfer_selector(i) {
                // Check if recipient comes from calldata
                if self.has_calldataload_before(i, 15) {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn is_transfer_selector(&self, pos: usize) -> bool {
        pos + 4 < self.bytecode.len()
            && self.bytecode[pos] == PUSH4
            && self.bytecode[pos+1] == 0xa9
            && self.bytecode[pos+2] == 0x05
    }

    fn has_calldataload_before(&self, pos: usize, range: usize) -> bool {
        if pos < range { return false; }
        
        for i in (pos.saturating_sub(range))..pos {
            if self.bytecode[i] == CALLDATALOAD {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frontend_injection_detection() {
        let bytecode = vec![
            CALLDATALOAD,                      // Load injected data
            SSTORE,                            // Store without validation
            CALLDATACOPY,
            DELEGATECALL,                      // Execute injected code
        ];
        let detector = FrontendInjectionAttackDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_safe_calldata_handling() {
        let bytecode = vec![
            CALLDATALOAD,
            LT,                                // Validation
            ISZERO,
            PUSH1, 0x08,
            JUMPI,
            REVERT,
            JUMPDEST,
            SSTORE,
        ];
        let detector = FrontendInjectionAttackDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
