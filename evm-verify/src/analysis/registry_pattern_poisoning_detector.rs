pub struct RegistryPatternPoisoningDetector {
    bytecode: Vec<u8>,
}

impl RegistryPatternPoisoningDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_registry_poisoning_risk() {
            findings.push("Registry pattern: Registry poisoning vulnerability detected".to_string());
        }

        if self.has_unvalidated_registration() {
            findings.push("Registry pattern: Unvalidated registration detected".to_string());
        }

        if self.has_registry_overwrite_risk() {
            findings.push("Registry pattern: Registry entry overwrite risk detected".to_string());
        }

        findings
    }

    fn has_registry_poisoning_risk(&self) -> bool {
        let registry_patterns: &[&[u8]] = &[
            b"register",
            b"Register",
            b"registry",
            b"addToRegistry",
        ];
        
        for pattern in registry_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }

    fn has_unvalidated_registration(&self) -> bool {
        let validation_patterns: &[&[u8]] = &[
            b"setRegistry",
            b"updateRegistry",
            b"registerAddress",
            b"addEntry",
        ];
        
        for pattern in validation_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }

    fn has_registry_overwrite_risk(&self) -> bool {
        let overwrite_patterns: &[&[u8]] = &[
            b"removeEntry",
            b"deleteRegistry",
            b"clearRegistry",
            b"unregister",
        ];
        
        for pattern in overwrite_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }
}
