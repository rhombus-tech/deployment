pub struct MockContractProductionUsageDetector {
    bytecode: Vec<u8>,
}

impl MockContractProductionUsageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_mock_function_patterns() {
            findings.push("Mock contract: Mock function patterns detected in production".to_string());
        }

        if self.has_test_double_interfaces() {
            findings.push("Mock contract: Test double interfaces found in production code".to_string());
        }

        if self.has_stubbed_implementations() {
            findings.push("Mock contract: Stubbed implementations in production contract".to_string());
        }

        findings
    }

    fn has_mock_function_patterns(&self) -> bool {
        // Check for mock/fake function names in bytecode
        let mock_patterns = [
            b"mock",
            b"Mock",
            b"MOCK",
            b"fake",
            b"Fake",
            b"stub",
            b"Stub",
        ];
        
        for pattern in &mock_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }

    fn has_test_double_interfaces(&self) -> bool {
        // Check for test double interface patterns (ITest, IMock prefix patterns)
        let interface_patterns = [
            b"ITest",
            b"IMock",
            b"IFake",
            b"TestDouble",
        ];
        
        for pattern in &interface_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        // Check for empty function implementations (JUMPDEST followed by immediate RETURN)
        for i in 0..self.bytecode.len().saturating_sub(2) {
            if self.bytecode[i] == 0x5b && self.bytecode[i + 1] == 0xf3 { // JUMPDEST + RETURN
                return true;
            }
        }
        
        false
    }

    fn has_stubbed_implementations(&self) -> bool {
        // Check for functions that always return zero or default values
        let mut stub_count = 0;
        
        for i in 0..self.bytecode.len().saturating_sub(3) {
            // Pattern: PUSH0/PUSH1 0 followed by RETURN
            if (self.bytecode[i] == 0x5f || (self.bytecode[i] == 0x60 && self.bytecode[i + 1] == 0x00)) {
                if i + 2 < self.bytecode.len() && self.bytecode[i + 2] == 0xf3 {
                    stub_count += 1;
                }
            }
        }
        
        // Multiple stubbed functions indicate mock contract
        stub_count > 3
    }
}
