pub struct EthCallGasLimitDosDetector {
    bytecode: Vec<u8>,
}

impl EthCallGasLimitDosDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_excessive_gas_consumption() {
            findings.push("eth_call DoS: Excessive gas consumption in view functions".to_string());
        }

        if self.has_unbounded_loops_in_view() {
            findings.push("eth_call DoS: Unbounded loops in view/pure functions".to_string());
        }

        if self.lacks_gas_estimation_limits() {
            findings.push("eth_call DoS: Missing gas estimation limits for static calls".to_string());
        }

        findings
    }

    fn has_excessive_gas_consumption(&self) -> bool {
        // Check for view/pure functions with high computational complexity
        // Look for STATICCALL (0xfa) which is used for view functions
        let mut staticcall_count = 0;
        let mut complex_operations = 0;
        
        for i in 0..self.bytecode.len() {
            match self.bytecode[i] {
                0xfa => staticcall_count += 1, // STATICCALL
                0x02 | 0x08 => complex_operations += 1, // MUL, EXP (expensive ops)
                _ => {}
            }
        }
        
        // Multiple staticcalls with complex operations = gas risk
        staticcall_count > 0 && complex_operations > 10
    }

    fn has_unbounded_loops_in_view(&self) -> bool {
        // Check for loop patterns in view functions
        let has_view_marker = self.bytecode.windows(4).any(|w| w == b"view" || w == b"pure");
        
        if has_view_marker {
            // Count JUMPI opcodes (loop indicators)
            let loop_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
            
            if loop_count > 0 {
                // Check for dynamic array length usage (unbounded)
                // Pattern: CALLDATALOAD followed by loop
                for i in 0..self.bytecode.len().saturating_sub(10) {
                    if self.bytecode[i] == 0x35 { // CALLDATALOAD
                        // Check for JUMPI within next 10 bytes
                        if self.bytecode[i..i+10].iter().any(|&b| b == 0x57) {
                            return true;
                        }
                    }
                }
            }
        }
        
        false
    }

    fn lacks_gas_estimation_limits(&self) -> bool {
        // Check for eth_call usage without gas limits
        let has_staticcall = self.bytecode.iter().any(|&b| b == 0xfa);
        
        if has_staticcall {
            // Look for gas parameter specification (GAS opcode 0x5a)
            let has_gas_spec = self.bytecode.iter().any(|&b| b == 0x5a);
            
            // Also check for explicit gas limit constants
            let mut has_gas_limit = false;
            for i in 0..self.bytecode.len().saturating_sub(2) {
                // PUSH followed by reasonable gas values
                if self.bytecode[i] >= 0x60 && self.bytecode[i] <= 0x64 {
                    has_gas_limit = true;
                    break;
                }
            }
            
            return !has_gas_spec && !has_gas_limit;
        }
        
        false
    }
}
