use serde::{Deserialize, Serialize};

/// CDS: Insurance against credit events
/// Trigger manipulation: Force/prevent credit event declaration

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditDefaultSwapVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CreditDefaultSwapTriggerDetector {
    bytecode: Vec<u8>,
}

impl CreditDefaultSwapTriggerDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<CreditDefaultSwapVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_credit_event_oracle_manipulation() {
            vulnerabilities.push(CreditDefaultSwapVulnerability {
                vulnerability_type: "Credit Event Oracle Manipulation".to_string(),
                location: loc,
                severity: "Critical".to_string(),
                description: "Credit event trigger relies on manipulatable oracle".to_string(),
                confidence: 0.85,
            });
        }
        vulnerabilities
    }
    fn has_credit_event_oracle_manipulation(&self) -> Option<usize> {
        // Credit event check without multi-sig or governance
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xfa { // STATICCALL (oracle)
                let mut has_multisig = false;
                for j in i+1..i+20.min(self.bytecode.len()) {
                    // Multisig: multiple CALLER/ORIGIN checks
                    if self.bytecode[j] == 0x33 { has_multisig = true; }
                }
                if !has_multisig { return Some(i); }
            }
        }
        None
    }
}
