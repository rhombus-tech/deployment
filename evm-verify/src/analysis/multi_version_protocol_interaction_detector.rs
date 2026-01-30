pub struct MultiVersionProtocolInteractionDetector {
    bytecode: Vec<u8>,
}

impl MultiVersionProtocolInteractionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_version_mismatch_risk() {
            findings.push("Protocol risk: Multi-version interaction mismatch detected".to_string());
        }

        if self.has_protocol_version_incompatibility() {
            findings.push("Protocol risk: Protocol version incompatibility detected".to_string());
        }

        if self.has_cross_version_state_corruption() {
            findings.push("Protocol risk: Cross-version state corruption risk detected".to_string());
        }

        findings
    }

    fn has_version_mismatch_risk(&self) -> bool {
        let version_patterns: &[&[u8]] = &[
            b"version",
            b"Version",
            b"protocolVersion",
            b"VERSION",
        ];
        
        for pattern in version_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }

    fn has_protocol_version_incompatibility(&self) -> bool {
        let protocol_patterns: &[&[u8]] = &[
            b"protocol",
            b"Protocol",
            b"checkVersion",
            b"verifyVersion",
        ];
        
        for pattern in protocol_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }

    fn has_cross_version_state_corruption(&self) -> bool {
        let corruption_patterns: &[&[u8]] = &[
            b"crossVersion",
            b"versionedCall",
            b"legacySupport",
            b"backward",
        ];
        
        for pattern in corruption_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }
}
