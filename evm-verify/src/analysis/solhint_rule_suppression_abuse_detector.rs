pub struct SolhintRuleSuppressionAbuseDetector {
    bytecode: Vec<u8>,
}

impl SolhintRuleSuppressionAbuseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<String> {
        let mut findings = Vec::new();

        if self.has_excessive_suppressions() {
            findings.push("Solhint abuse: Excessive rule suppressions hiding vulnerabilities".to_string());
        }

        if self.has_critical_rule_suppressions() {
            findings.push("Solhint abuse: Critical security rules suppressed".to_string());
        }

        if self.has_blanket_suppressions() {
            findings.push("Solhint abuse: Blanket rule suppressions across entire contract".to_string());
        }

        findings
    }

    fn has_excessive_suppressions(&self) -> bool {
        // Check for solhint-disable comments
        let suppression_patterns = [
            b"solhint-disable",
            b"solhint-disable-next-line",
            b"solhint-disable-line",
        ];
        
        let mut suppression_count = 0;
        for pattern in &suppression_patterns {
            suppression_count += self.bytecode.windows(pattern.len())
                .filter(|w| *w == *pattern)
                .count();
        }
        
        // More than 5 suppressions is suspicious
        suppression_count > 5
    }

    fn has_critical_rule_suppressions(&self) -> bool {
        // Check for suppression of security-critical rules
        let critical_rules = [
            b"reentrancy",
            b"no-unused-vars",
            b"check-send-result",
            b"avoid-tx-origin",
            b"avoid-call-value",
            b"no-inline-assembly",
        ];
        
        for rule in &critical_rules {
            if self.bytecode.windows(rule.len()).any(|w| w == *rule) {
                // Check if there's a disable nearby
                return true;
            }
        }
        
        false
    }

    fn has_blanket_suppressions(&self) -> bool {
        // Check for file-level suppressions (/* solhint-disable */)
        let blanket_patterns = [
            b"/* solhint-disable */",
            b"// solhint-disable",
        ];
        
        for pattern in &blanket_patterns {
            if self.bytecode.windows(pattern.len()).any(|w| w == *pattern) {
                return true;
            }
        }
        
        false
    }
}
