pub struct ProxyImplementationSelectorCollisionDetector {
    bytecode: Vec<u8>,
}

impl ProxyImplementationSelectorCollisionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_selector_collision_risk() {
            findings.push("Proxy pattern: Function selector collision risk detected".to_string());
        }

        if self.has_implementation_slot_conflict() {
            findings.push("Proxy pattern: Implementation storage slot conflict detected".to_string());
        }

        if self.has_delegatecall_selector_clash() {
            findings.push("Proxy pattern: Delegatecall selector clash vulnerability".to_string());
        }

        findings
    }

    fn has_selector_collision_risk(&self) -> bool {
        let selector_patterns: &[&[u8]] = &[
            b"implementation",
            b"Implementation",
            b"upgradeTo",
            b"delegatecall",
        ];
        
        for pattern in selector_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }

    fn has_implementation_slot_conflict(&self) -> bool {
        let slot_patterns: &[&[u8]] = &[
            b"IMPLEMENTATION_SLOT",
            b"implementationSlot",
            b"storageSlot",
            b"slot",
        ];
        
        for pattern in slot_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }

    fn has_delegatecall_selector_clash(&self) -> bool {
        let clash_patterns: &[&[u8]] = &[
            b"fallback",
            b"receive",
            b"proxy",
            b"delegate",
        ];
        
        for pattern in clash_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }
}
