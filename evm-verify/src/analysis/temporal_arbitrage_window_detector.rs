use serde::{Deserialize, Serialize};

/// Temporal Arbitrage: Time windows between events create arb opportunities
/// Attack: Exploit delay between oracle updates, cross-chain messages, etc.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporalArbitrageVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TemporalArbitrageWindowDetector {
    bytecode: Vec<u8>,
}

impl TemporalArbitrageWindowDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<TemporalArbitrageVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_stale_data_window() {
            vulnerabilities.push(TemporalArbitrageVulnerability {
                vulnerability_type: "Stale Data Temporal Window".to_string(),
                location: loc,
                severity: "Critical".to_string(),
                description: "Data not updated immediately, creating arbitrage window".to_string(),
                confidence: 0.90,
            });
        }
        vulnerabilities
    }
    fn has_stale_data_window(&self) -> Option<usize> {
        // Oracle call without freshness check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xfa { // STATICCALL (oracle)
                let mut has_freshness_check = false;
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x42 { // TIMESTAMP comparison
                        has_freshness_check = true;
                    }
                }
                if !has_freshness_check { return Some(i); }
            }
        }
        None
    }
}
