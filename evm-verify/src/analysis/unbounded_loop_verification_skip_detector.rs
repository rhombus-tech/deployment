pub struct UnboundedLoopVerificationSkipDetector {
    bytecode: Vec<u8>,
}

impl UnboundedLoopVerificationSkipDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_unbounded_loops() {
            findings.push("Unbounded loop: Unbounded loop detected without verification".to_string());
        }

        if self.has_dynamic_array_iteration() {
            findings.push("Unbounded loop: Dynamic array iteration without bounds checking".to_string());
        }

        if self.has_user_controlled_loop_bounds() {
            findings.push("Unbounded loop: User-controlled loop bounds vulnerability".to_string());
        }

        findings
    }

    fn has_unbounded_loops(&self) -> bool {
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x56 || self.bytecode[i] == 0x57 {
                let has_bound_check = (i..i.min(self.bytecode.len()).min(i + 20))
                    .any(|j| self.bytecode[j] == 0x10 || self.bytecode[j] == 0x12);
                
                if !has_bound_check {
                    return true;
                }
            }
        }
        
        false
    }

    fn has_dynamic_array_iteration(&self) -> bool {
        let array_patterns: &[&[u8]] = &[
            b"length",
            b"size",
            b"count",
        ];
        
        for pattern in array_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                let has_jump = self.bytecode.iter().any(|&b| b == 0x56 || b == 0x57);
                if has_jump {
                    return true;
                }
            }
        }
        
        false
    }

    fn has_user_controlled_loop_bounds(&self) -> bool {
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x35 {
                if (i..i.min(self.bytecode.len()).min(i + 10))
                    .any(|j| self.bytecode[j] == 0x56 || self.bytecode[j] == 0x57)
                {
                    return true;
                }
            }
        }
        
        false
    }
}
