use crate::bytecode::opcodes::*;

pub struct CrossProtocolReentrancyDetector {
    bytecode: Vec<u8>,
}

impl CrossProtocolReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_cross_protocol_calls()
            && self.has_state_changes_after_external_calls()
            && !self.has_reentrancy_guards()
    }

    fn has_cross_protocol_calls(&self) -> bool {
        // Multiple external CALLs indicating cross-protocol interaction
        let call_count = self.bytecode.iter()
            .filter(|&&op| op == CALL || op == DELEGATECALL || op == STATICCALL)
            .count();
        
        call_count >= 2
    }

    fn has_state_changes_after_external_calls(&self) -> bool {
        // SSTORE after CALL (state changes post external call)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(20) {
            if self.is_external_call(self.bytecode[i]) {
                // Look for SSTORE after call
                for j in i+1..i.min(self.bytecode.len()).min(i+15) {
                    if self.bytecode[j] == SSTORE {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn is_external_call(&self, opcode: u8) -> bool {
        matches!(opcode, CALL | DELEGATECALL | CALLCODE)
    }

    fn has_reentrancy_guards(&self) -> bool {
        // Check for reentrancy guard pattern
        self.has_mutex_pattern() || self.has_checks_effects_interactions()
    }

    fn has_mutex_pattern(&self) -> bool {
        // SLOAD -> check -> SSTORE (lock) -> ... -> SSTORE (unlock)
        let mut sstore_count = 0;
        let mut has_initial_check = false;

        for (i, &opcode) in self.bytecode.iter().enumerate() {
            if opcode == SLOAD && i + 5 < self.bytecode.len() {
                // Check if followed by conditional
                if self.bytecode[i+1] == ISZERO || self.bytecode[i+2] == ISZERO {
                    has_initial_check = true;
                }
            }
            if opcode == SSTORE {
                sstore_count += 1;
            }
        }

        has_initial_check && sstore_count >= 2
    }

    fn has_checks_effects_interactions(&self) -> bool {
        // State changes (SSTORE) before external calls
        let mut i = 0;
        let mut found_proper_order = false;

        while i < self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == SSTORE {
                // Check if CALL comes after
                for j in i+1..i.min(self.bytecode.len()).min(i+15) {
                    if self.is_external_call(self.bytecode[j]) {
                        found_proper_order = true;
                        break;
                    }
                }
            }
            i += 1;
        }

        found_proper_order
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cross_protocol_reentrancy() {
        let bytecode = vec![
            CALL,               // External call 1
            CALL,               // External call 2 (cross-protocol)
            SSTORE,             // State change after calls
        ];
        let detector = CrossProtocolReentrancyDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_protected_cross_protocol() {
        let bytecode = vec![
            SLOAD, ISZERO,      // Guard check
            SSTORE,             // Lock
            CALL,               // External call
            SSTORE,             // Unlock
        ];
        let detector = CrossProtocolReentrancyDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
