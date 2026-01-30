use serde::{Deserialize, Serialize};

/// VWAP (Volume-Weighted Average Price) Manipulation Detector
/// VWAP = Σ(price × volume) / Σ(volume)
/// Attackers can manipulate by controlling volume distribution

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightedAverageVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct WeightedAverageManipulationDetector {
    bytecode: Vec<u8>,
}

impl WeightedAverageManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<WeightedAverageVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_vwap_without_volume_check() {
            vulnerabilities.push(WeightedAverageVulnerability {
                vulnerability_type: "VWAP Without Volume Validation".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "VWAP calculation lacks volume manipulation checks".to_string(),
                confidence: 0.85,
            });
        }
        if let Some(loc) = self.has_weighted_average_overflow() {
            vulnerabilities.push(WeightedAverageVulnerability {
                vulnerability_type: "Weighted Average Overflow Risk".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Weight × value multiplication can overflow".to_string(),
                confidence: 0.75,
            });
        }
        vulnerabilities
    }
    fn has_vwap_without_volume_check(&self) -> Option<usize> {
        // Pattern: MUL (price×volume) + accumulation without min volume
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x02 { // MUL (price × volume)
                let mut has_accumulation = false;
                let mut has_min_check = false;
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x01 { has_accumulation = true; } // ADD
                    if self.bytecode[j] == 0x10 { has_min_check = true; } // LT (min check)
                }
                if has_accumulation && !has_min_check {
                    return Some(i);
                }
            }
        }
        None
    }
    fn has_weighted_average_overflow(&self) -> Option<usize> {
        // Pattern: MUL + DIV without overflow protection
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x02 && // MUL
               self.bytecode.get(i+5) == Some(&0x04) { // DIV
                return Some(i);
            }
        }
        None
    }
}
