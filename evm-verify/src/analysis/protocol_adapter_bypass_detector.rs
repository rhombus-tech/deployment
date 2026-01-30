use crate::bytecode::opcodes::*;

pub struct ProtocolAdapterBypassDetector {
    bytecode: Vec<u8>,
}

impl ProtocolAdapterBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_adapter_pattern()
            && (self.has_access_control_bypass() || self.has_validation_bypass())
    }

    fn has_adapter_pattern(&self) -> bool {
        // Adapter wraps external protocol calls
        self.has_delegatecall_pattern() || self.has_wrapper_functions()
    }

    fn has_delegatecall_pattern(&self) -> bool {
        // DELEGATECALL to external implementation
        self.bytecode.iter().any(|&op| op == DELEGATECALL)
    }

    fn has_wrapper_functions(&self) -> bool {
        // Multiple CALL operations wrapping external protocols
        let call_count = self.bytecode.iter()
            .filter(|&&op| op == CALL)
            .count();
        
        call_count >= 3
    }

    fn has_access_control_bypass(&self) -> bool {
        // Direct external calls without proper authorization checks
        self.has_unprotected_external_calls() || self.has_missing_caller_validation()
    }

    fn has_unprotected_external_calls(&self) -> bool {
        // CALL without preceding CALLER/ORIGIN check
        let mut i = 0;
        while i < self.bytecode.len() {
            if self.bytecode[i] == CALL || self.bytecode[i] == DELEGATECALL {
                // Check if there's CALLER validation before
                if !self.has_caller_check_before(i) {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_caller_check_before(&self, call_pos: usize) -> bool {
        if call_pos < 15 { return false; }
        
        for i in (call_pos.saturating_sub(15))..call_pos {
            if self.bytecode[i] == CALLER || self.bytecode[i] == ORIGIN {
                // Check for comparison
                for j in i+1..call_pos.min(i+10) {
                    if matches!(self.bytecode[j], EQ | ISZERO) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_missing_caller_validation(&self) -> bool {
        // DELEGATECALL without msg.sender preservation check
        let has_delegatecall = self.bytecode.iter().any(|&op| op == DELEGATECALL);
        let has_caller_storage = self.has_caller_in_storage();
        
        has_delegatecall && !has_caller_storage
    }

    fn has_caller_in_storage(&self) -> bool {
        // CALLER followed by SSTORE (storing for validation)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == CALLER {
                for j in i+1..i.min(self.bytecode.len()).min(i+8) {
                    if self.bytecode[j] == SSTORE {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_validation_bypass(&self) -> bool {
        // Bypass adapter validation through direct protocol access
        self.has_multiple_entry_points() && self.has_inconsistent_validation()
    }

    fn has_multiple_entry_points(&self) -> bool {
        // Multiple JUMPDEST indicating different function entries
        let jumpdest_count = self.bytecode.iter()
            .filter(|&&op| op == JUMPDEST)
            .count();
        
        jumpdest_count >= 5
    }

    fn has_inconsistent_validation(&self) -> bool {
        // Some paths have validation, others don't
        let mut paths_with_validation = 0;
        let mut paths_without_validation = 0;
        let mut i = 0;

        while i < self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == JUMPDEST {
                // Check if this path has CALLER validation
                let mut has_validation = false;
                let mut has_call = false;

                for j in i+1..i.min(self.bytecode.len()).min(i+25) {
                    if self.bytecode[j] == CALLER {
                        has_validation = true;
                    }
                    if self.bytecode[j] == CALL || self.bytecode[j] == DELEGATECALL {
                        has_call = true;
                        break;
                    }
                }

                if has_call {
                    if has_validation {
                        paths_with_validation += 1;
                    } else {
                        paths_without_validation += 1;
                    }
                }
            }
            i += 1;
        }

        paths_with_validation > 0 && paths_without_validation > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adapter_bypass_detection() {
        let bytecode = vec![
            JUMPDEST,                           // Entry point 1
            CALLER, EQ,                         // Validation
            DELEGATECALL,                       // Protected call
            JUMPDEST,                           // Entry point 2
            DELEGATECALL,                       // Unprotected call (bypass)
        ];
        let detector = ProtocolAdapterBypassDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_safe_adapter() {
        let bytecode = vec![
            CALLER, SSTORE,                     // Store caller
            DELEGATECALL,                       // Protected call
            CALLER, EQ,                         // Validate
        ];
        let detector = ProtocolAdapterBypassDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
