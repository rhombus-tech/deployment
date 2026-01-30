pub struct TestModeDeploymentDetector {
    bytecode: Vec<u8>,
}

impl TestModeDeploymentDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_test_mode_flag() {
            findings.push("Test mode: Test mode flag detected in production deployment".to_string());
        }

        if self.has_debug_mode_enabled() {
            findings.push("Test mode: Debug mode enabled in production contract".to_string());
        }

        if self.has_test_account_privileges() {
            findings.push("Test mode: Test account privileges present in production".to_string());
        }

        findings
    }

    fn has_test_mode_flag(&self) -> bool {
        // Check for test mode flags in bytecode (common patterns in test contracts)
        let test_patterns = [
            b"TEST_MODE",
            b"__TEST__",
            b"IS_TEST",
            b"TESTING",
        ];
        
        for pattern in &test_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        // Check for hardcoded test flag storage slots
        for i in 0..self.bytecode.len().saturating_sub(33) {
            if self.bytecode[i] == 0x60 && i + 2 < self.bytecode.len() {
                let slot = self.bytecode[i + 1];
                if slot == 0xFF || slot == 0xFE { // Common test flag slots
                    return true;
                }
            }
        }
        
        false
    }

    fn has_debug_mode_enabled(&self) -> bool {
        // Check for debug logging patterns
        let debug_patterns = [
            b"DEBUG",
            b"debug",
            b"LOG_LEVEL",
        ];
        
        for pattern in &debug_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        // Check for excessive LOG opcodes (LOG0-LOG4: 0xa0-0xa4)
        let log_count = self.bytecode.iter().filter(|&&b| b >= 0xa0 && b <= 0xa4).count();
        if log_count > 20 { // Unusual amount of logging
            return true;
        }
        
        false
    }

    fn has_test_account_privileges(&self) -> bool {
        // Check for hardcoded test addresses (common patterns: 0xdead, 0xbeef, etc.)
        let test_addresses = [
            vec![0xde, 0xad, 0xbe, 0xef],
            vec![0xca, 0xfe, 0xba, 0xbe],
            vec![0x00, 0x00, 0x00, 0x00],
        ];
        
        for addr_pattern in &test_addresses {
            if self.bytecode.windows(addr_pattern.len()).any(|w| w == addr_pattern.as_slice()) {
                return true;
            }
        }
        
        // Check for bypass patterns (checking caller against test address)
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x33 { // CALLER
                if i + 4 < self.bytecode.len() && self.bytecode[i + 1] == 0x73 { // PUSH20 after CALLER
                    return true; // Likely hardcoded address check
                }
            }
        }
        
        false
    }
}
