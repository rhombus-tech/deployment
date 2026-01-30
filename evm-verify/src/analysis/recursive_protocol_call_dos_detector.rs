use crate::bytecode::opcodes::*;

pub struct RecursiveProtocolCallDosDetector {
    bytecode: Vec<u8>,
}

impl RecursiveProtocolCallDosDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> bool {
        self.has_recursive_call_pattern()
            && (self.has_unbounded_recursion() || self.has_gas_exhaustion_risk())
    }

    fn has_recursive_call_pattern(&self) -> bool {
        // Function calls itself or creates call loop
        self.has_self_call() || self.has_call_loop()
    }

    fn has_self_call(&self) -> bool {
        // ADDRESS followed by CALL (calling itself)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == ADDRESS {
                for j in i+1..i.min(self.bytecode.len()).min(i+12) {
                    if self.bytecode[j] == CALL {
                        return true;
                    }
                }
            }
            i += 1;
        }
        false
    }

    fn has_call_loop(&self) -> bool {
        // CALL inside a loop (JUMPI back)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == JUMPDEST {
                let mut has_call = false;
                let mut has_jump_back = false;

                for j in i+1..i.min(self.bytecode.len()).min(i+20) {
                    if self.bytecode[j] == CALL {
                        has_call = true;
                    }
                    if self.bytecode[j] == JUMPI {
                        has_jump_back = true;
                    }
                }

                if has_call && has_jump_back {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_unbounded_recursion(&self) -> bool {
        // Recursion without depth check
        self.has_recursive_call_pattern() && !self.has_depth_limit()
    }

    fn has_depth_limit(&self) -> bool {
        // Counter/depth check before recursive call
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(20) {
            // Look for counter increment/check pattern
            if self.bytecode[i] == SLOAD {
                let mut has_comparison = false;
                let mut has_increment = false;

                for j in i+1..i.min(self.bytecode.len()).min(i+15) {
                    if matches!(self.bytecode[j], LT | GT | EQ) {
                        has_comparison = true;
                    }
                    if self.bytecode[j] == ADD {
                        has_increment = true;
                    }
                }

                if has_comparison && has_increment {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_gas_exhaustion_risk(&self) -> bool {
        // High gas consumption in recursive calls
        self.has_expensive_operations_in_loop() || self.has_unbounded_iteration()
    }

    fn has_expensive_operations_in_loop(&self) -> bool {
        // Loop with SSTORE/CALL (expensive operations)
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == JUMPDEST {
                let mut has_expensive_op = false;
                let mut has_loop = false;

                for j in i+1..i.min(self.bytecode.len()).min(i+20) {
                    if self.bytecode[j] == SSTORE || self.bytecode[j] == CALL {
                        has_expensive_op = true;
                    }
                    if self.bytecode[j] == JUMPI {
                        has_loop = true;
                    }
                }

                if has_expensive_op && has_loop {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    fn has_unbounded_iteration(&self) -> bool {
        // Loop without clear termination condition
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == JUMPDEST {
                let mut has_jumpi = false;
                let mut has_condition = false;

                for j in i+1..i.min(self.bytecode.len()).min(i+20) {
                    if self.bytecode[j] == JUMPI {
                        has_jumpi = true;
                    }
                    // Check for termination condition
                    if matches!(self.bytecode[j], ISZERO | LT | GT | EQ) {
                        has_condition = true;
                    }
                }

                // Loop without proper termination condition
                if has_jumpi && !has_condition {
                    return true;
                }
            }
            i += 1;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recursive_dos_detection() {
        let bytecode = vec![
            JUMPDEST,                           // Loop start
            ADDRESS,                            // Get own address
            CALL,                               // Recursive call
            SSTORE,                             // Expensive operation
            PUSH1, 0x00,
            JUMPI,                              // Loop back (unbounded)
        ];
        let detector = RecursiveProtocolCallDosDetector::new(bytecode);
        assert!(detector.detect());
    }

    #[test]
    fn test_safe_recursion() {
        let bytecode = vec![
            SLOAD,                              // Load depth counter
            PUSH1, 0x0A, LT,                    // Check depth < 10
            ISZERO, PUSH1, 0x08, JUMPI,
            REVERT,                             // Revert if too deep
            JUMPDEST,
            ADDRESS, CALL,                      // Safe recursive call
        ];
        let detector = RecursiveProtocolCallDosDetector::new(bytecode);
        assert!(!detector.detect());
    }
}
