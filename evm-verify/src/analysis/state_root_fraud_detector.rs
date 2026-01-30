use serde::{Deserialize, Serialize};

/// State Root Fraud: False state roots submitted to L1
/// Attack: Submit invalid state root, withdraw before challenge

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateRootFraudVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct StateRootFraudDetector {
    bytecode: Vec<u8>,
}

impl StateRootFraudDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<StateRootFraudVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_weak_fraud_proof() {
            vulnerabilities.push(StateRootFraudVulnerability {
                vulnerability_type: "Insufficient Fraud Proof Window".to_string(),
                location: loc,
                severity: "Critical".to_string(),
                description: "State root finalization without adequate challenge period".to_string(),
                confidence: 0.85,
            });
        }
        vulnerabilities
    }
    fn has_weak_fraud_proof(&self) -> Option<usize> {
        // State root update without challenge period
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 { // SSTORE (state root)
                let mut has_delay = false;
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x42 { // TIMESTAMP (delay check)
                        has_delay = true;
                    }
                }
                if !has_delay { return Some(i); }
            }
        }
        None
    }
}
