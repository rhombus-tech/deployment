pub struct BackwardsCompatibilityBreakDetector {
    bytecode: Vec<u8>,
}

impl BackwardsCompatibilityBreakDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_interface_breaking_change() {
            findings.push("Version risk: Interface breaking change detected".to_string());
        }

        if self.has_storage_layout_incompatibility() {
            findings.push("Version risk: Storage layout incompatibility detected".to_string());
        }

        if self.has_abi_compatibility_issue() {
            findings.push("Version risk: ABI compatibility issue detected".to_string());
        }

        findings
    }

    fn has_interface_breaking_change(&self) -> bool {
        let interface_patterns: &[&[u8]] = &[
            b"interface",
            b"Interface",
            b"supportsInterface",
            b"version",
        ];
        
        for pattern in interface_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }

    fn has_storage_layout_incompatibility(&self) -> bool {
        let storage_patterns: &[&[u8]] = &[
            b"storageLayout",
            b"storageSlot",
            b"slot",
            b"offset",
        ];
        
        for pattern in storage_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }

    fn has_abi_compatibility_issue(&self) -> bool {
        let abi_patterns: &[&[u8]] = &[
            b"signature",
            b"selector",
            b"functionSig",
            b"methodId",
        ];
        
        for pattern in abi_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }
}
