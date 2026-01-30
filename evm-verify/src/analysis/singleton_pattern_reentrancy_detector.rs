pub struct SingletonPatternReentrancyDetector {
    bytecode: Vec<u8>,
}

impl SingletonPatternReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_singleton_reentrancy_risk() {
            findings.push("Singleton pattern: Reentrancy vulnerability in singleton detected".to_string());
        }

        if self.has_shared_state_mutation() {
            findings.push("Singleton pattern: Shared state mutation risk detected".to_string());
        }

        if self.has_unprotected_singleton_access() {
            findings.push("Singleton pattern: Unprotected singleton access detected".to_string());
        }

        findings
    }

    fn has_singleton_reentrancy_risk(&self) -> bool {
        let singleton_patterns: &[&[u8]] = &[
            b"getInstance",
            b"instance",
            b"singleton",
            b"Singleton",
        ];
        
        for pattern in singleton_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }

    fn has_shared_state_mutation(&self) -> bool {
        let state_patterns: &[&[u8]] = &[
            b"sharedState",
            b"globalState",
            b"updateState",
            b"setState",
        ];
        
        for pattern in state_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }

    fn has_unprotected_singleton_access(&self) -> bool {
        let access_patterns: &[&[u8]] = &[
            b"getOrCreate",
            b"initialize",
            b"setup",
            b"init",
        ];
        
        for pattern in access_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }
}
