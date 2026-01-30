pub struct IncompleteTestCoverageDeploymentDetector {
    bytecode: Vec<u8>,
}

impl IncompleteTestCoverageDeploymentDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_untested_functions() {
            findings.push("Test coverage: Untested functions detected in production deployment".to_string());
        }

        if self.has_low_branch_coverage() {
            findings.push("Test coverage: Low branch coverage in deployed contract".to_string());
        }

        if self.has_untested_edge_cases() {
            findings.push("Test coverage: Critical edge cases not tested before deployment".to_string());
        }

        findings
    }

    fn has_untested_functions(&self) -> bool {
        // Detect complex functions without proper coverage indicators
        let mut function_boundaries = Vec::new();
        
        // Find JUMPDEST opcodes (function entry points)
        for (i, &byte) in self.bytecode.iter().enumerate() {
            if byte == 0x5b { // JUMPDEST
                function_boundaries.push(i);
            }
        }
        
        // Check if there are many functions (>10) which might indicate untested code paths
        if function_boundaries.len() > 10 {
            // Check for functions with minimal logic (likely untested stubs)
            let mut stub_functions = 0;
            for &pos in &function_boundaries {
                if pos + 5 < self.bytecode.len() {
                    let next_bytes = &self.bytecode[pos+1..pos+5];
                    // Simple return pattern indicates stub
                    if next_bytes[0] == 0x60 && next_bytes[2] == 0xf3 {
                        stub_functions += 1;
                    }
                }
            }
            return stub_functions > 3;
        }
        
        false
    }

    fn has_low_branch_coverage(&self) -> bool {
        // Count conditional jumps vs total jumps
        let mut conditional_jumps = 0;
        let mut total_jumps = 0;
        
        for i in 0..self.bytecode.len() {
            match self.bytecode[i] {
                0x56 => total_jumps += 1,      // JUMP
                0x57 => {                      // JUMPI
                    conditional_jumps += 1;
                    total_jumps += 1;
                }
                _ => {}
            }
        }
        
        // If there are many conditional branches but low overall complexity,
        // it might indicate untested branches
        if conditional_jumps > 5 {
            // Check for error handling patterns (REVERT, INVALID)
            let error_handlers = self.bytecode.iter()
                .filter(|&&b| b == 0xfd || b == 0xfe)
                .count();
            
            // Low error handling vs high branching = poor coverage
            return error_handlers < conditional_jumps / 2;
        }
        
        false
    }

    fn has_untested_edge_cases(&self) -> bool {
        // Check for missing overflow/underflow checks in arithmetic
        let mut has_arithmetic = false;
        let mut has_checks = false;
        
        for i in 0..self.bytecode.len() {
            match self.bytecode[i] {
                0x01 | 0x02 | 0x03 | 0x04 => { // ADD, MUL, SUB, DIV
                    has_arithmetic = true;
                }
                0x57 => { // JUMPI (conditional check)
                    if has_arithmetic {
                        has_checks = true;
                    }
                }
                0xfd => { // REVERT (error handling)
                    has_checks = true;
                }
                _ => {}
            }
        }
        
        // Arithmetic without checks indicates missing edge case tests
        has_arithmetic && !has_checks
    }
}
