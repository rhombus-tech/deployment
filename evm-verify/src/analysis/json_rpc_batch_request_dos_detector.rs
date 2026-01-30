pub struct JsonRpcBatchRequestDosDetector {
    bytecode: Vec<u8>,
}

impl JsonRpcBatchRequestDosDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_unbounded_batch_requests() {
            findings.push("JSON-RPC DoS: Unbounded batch request size vulnerability".to_string());
        }

        if self.lacks_batch_size_limits() {
            findings.push("JSON-RPC DoS: Missing batch size limits on RPC endpoint".to_string());
        }

        if self.has_batch_amplification_attack() {
            findings.push("JSON-RPC DoS: Batch amplification attack pattern detected".to_string());
        }

        findings
    }

    fn has_unbounded_batch_requests(&self) -> bool {
        // Check for batch request handling without size limits
        let has_batch = self.bytecode.windows(5).any(|w| w == b"batch" || w == b"Batch");
        
        if has_batch {
            // Look for array/length checking patterns
            let size_check_patterns: &[&[u8]] = &[
                b"length",
                b"size",
                b"count",
                b"limit",
            ];
            
            let has_size_check = size_check_patterns.iter()
                .any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            // Check for comparison opcodes near batch operations
            let mut has_comparison = false;
            for i in 0..self.bytecode.len().saturating_sub(10) {
                if self.bytecode[i..].windows(5).any(|w| w == b"batch") {
                    // Look for LT, GT, EQ opcodes nearby
                    let nearby = &self.bytecode[i.saturating_sub(10)..i.saturating_add(20).min(self.bytecode.len())];
                    if nearby.iter().any(|&b| b == 0x10 || b == 0x11 || b == 0x14) {
                        has_comparison = true;
                        break;
                    }
                }
            }
            
            return !has_size_check && !has_comparison;
        }
        
        false
    }

    fn lacks_batch_size_limits(&self) -> bool {
        // Check for JSON-RPC batch operations without explicit limits
        let rpc_patterns: &[&[u8]] = &[b"rpc", b"RPC", b"json", b"JSON"];
        let has_rpc = rpc_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        let has_batch = self.bytecode.windows(5).any(|w| w == b"batch");
        
        if has_rpc && has_batch {
            // Look for numeric limits (e.g., max batch size constants)
            let common_limits = [10u8, 20, 50, 100, 255];
            let mut has_limit_constant = false;
            
            for &limit in &common_limits {
                // PUSH1 followed by common limit values
                for i in 0..self.bytecode.len().saturating_sub(2) {
                    if self.bytecode[i] == 0x60 && self.bytecode[i + 1] == limit {
                        has_limit_constant = true;
                        break;
                    }
                }
            }
            
            return !has_limit_constant;
        }
        
        false
    }

    fn has_batch_amplification_attack(&self) -> bool {
        // Check for patterns indicating batch request amplification
        let has_batch = self.bytecode.windows(5).any(|w| w == b"batch");
        
        if has_batch {
            // Look for loop patterns that could amplify requests
            let mut loop_count = 0;
            for i in 0..self.bytecode.len() {
                // JUMPI opcode indicates loop
                if self.bytecode[i] == 0x57 {
                    loop_count += 1;
                }
            }
            
            // Multiple loops with batch operations = amplification risk
            if loop_count > 2 {
                return true;
            }
            
            // Check for nested call patterns
            let call_count = self.bytecode.iter()
                .filter(|&&b| b == 0xf1 || b == 0xf4 || b == 0xfa) // CALL, DELEGATECALL, STATICCALL
                .count();
            
            return call_count > 5;
        }
        
        false
    }
}
