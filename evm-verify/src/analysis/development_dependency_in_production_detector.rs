pub struct DevelopmentDependencyInProductionDetector {
    bytecode: Vec<u8>,
}

impl DevelopmentDependencyInProductionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_dev_dependency_imports() {
            findings.push("Dev dependency: Development library imported in production code".to_string());
        }

        if self.has_test_framework_code() {
            findings.push("Dev dependency: Test framework code found in production contract".to_string());
        }

        if self.has_debug_library_usage() {
            findings.push("Dev dependency: Debug library used in production deployment".to_string());
        }

        findings
    }

    fn has_dev_only_libraries(&self) -> bool {
        // Check for development library patterns
        let dev_lib_patterns = [
            b"console.sol",
            b"console2.sol",
            b"forge-std",
            b"Test.sol",
            b"Script.sol",
            b"Vm.sol",
            b"StdUtils",
            b"StdCheats",
        ];
        
        for pattern in &dev_lib_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        // Check for hardhat console imports
        if self.bytecode.windows(7).any(|w| w == b"console") {
            return true;
        }
        
        false
    }

    fn has_debugging_code(&self) -> bool {
        // Check for console.log selectors (Hardhat console)
        let console_log_selector = [0x2c, 0x2e, 0xce, 0xeb]; // console.log(string)
        if self.bytecode.windows(4).any(|w| w == &console_log_selector) {
            return true;
        }
        
        // Check for excessive LOG opcodes (debugging)
        let log_count = self.bytecode.iter()
            .filter(|&&b| b >= 0xa0 && b <= 0xa4)
            .count();
        
        if log_count > 15 {
            return true;
        }
        
        // Check for debug strings
        let debug_strings = [b"DEBUG:", b"[DEBUG]", b"console.log"];
        for pattern in &debug_strings {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }

    fn has_test_helpers_imported(&self) -> bool {
        // Check for test helper function names
        let test_helpers = [
            b"setUp",
            b"testFail",
            b"testFuzz",
            b"invariant_",
            b"test_",
            b"expectRevert",
            b"expectEmit",
            b"prank",
            b"startPrank",
            b"stopPrank",
            b"deal",
            b"hoax",
        ];
        
        let mut helper_count = 0;
        for pattern in &test_helpers {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                helper_count += 1;
                if helper_count >= 2 {
                    return true;
                }
            }
        }
        
        false
    }
    
    fn has_dev_dependency_imports(&self) -> bool {
        self.has_dev_only_libraries()
    }
    
    fn has_test_framework_code(&self) -> bool {
        self.has_test_helpers_imported()
    }
    
    fn has_debug_library_usage(&self) -> bool {
        self.has_debugging_code()
    }
}
