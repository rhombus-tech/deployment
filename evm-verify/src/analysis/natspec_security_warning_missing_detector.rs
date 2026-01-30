pub struct NatspecSecurityWarningMissingDetector {
    bytecode: Vec<u8>,
}

impl NatspecSecurityWarningMissingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_high_risk_functions_without_warnings() {
            findings.push("NatSpec missing: High-risk functions lack security warnings in documentation".to_string());
        }

        if self.has_external_calls_without_docs() {
            findings.push("NatSpec missing: External calls lack risk documentation".to_string());
        }

        if self.has_privileged_functions_without_warnings() {
            findings.push("NatSpec missing: Privileged functions lack access control warnings".to_string());
        }

        findings
    }

    fn has_high_risk_functions_without_warnings(&self) -> bool {
        // Check for high-risk operations (CALL, DELEGATECALL, SELFDESTRUCT)
        let has_high_risk = self.bytecode.iter().any(|&b| 
            b == 0xf1 || // CALL
            b == 0xf4 || // DELEGATECALL
            b == 0xff    // SELFDESTRUCT
        );
        
        if has_high_risk {
            // Look for NatSpec documentation markers
            let doc_patterns: &[&[u8]] = &[b"@notice", b"@dev", b"@custom:security", b"@warning"];
            let has_docs = doc_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            
            return !has_docs;
        }
        
        false
    }

    fn has_external_calls_without_docs(&self) -> bool {
        // Check for external calls
        let call_count = self.bytecode.iter()
            .filter(|&&b| b == 0xf1 || b == 0xf4 || b == 0xfa)
            .count();
        
        if call_count > 0 {
            // Check for documentation about external call risks
            let risk_docs: &[&[u8]] = &[
                b"reentrancy",
                b"external call",
                b"@custom:security",
            ];
            
            let has_risk_docs = risk_docs.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            return !has_risk_docs;
        }
        
        false
    }

    fn has_privileged_functions_without_warnings(&self) -> bool {
        // Check for owner/admin patterns
        let privilege_patterns: &[&[u8]] = &[b"owner", b"admin", b"onlyOwner", b"onlyAdmin"];
        let has_privilege = privilege_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
        
        if has_privilege {
            // Look for access control warnings
            let warning_patterns: &[&[u8]] = &[
                b"@notice Only",
                b"@dev Restricted",
                b"@custom:access",
            ];
            
            let has_warnings = warning_patterns.iter().any(|p| self.bytecode.windows(p.len()).any(|w| w == *p));
            return !has_warnings;
        }
        
        false
    }
}
