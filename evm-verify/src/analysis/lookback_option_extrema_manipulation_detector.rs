use serde::{Deserialize, Serialize};

/// Lookback Option: Payoff based on max/min price during period
/// Attack: Flash crash/pump to set extreme

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LookbackOptionVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct LookbackOptionExtremaManipulationDetector {
    bytecode: Vec<u8>,
}

impl LookbackOptionExtremaManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<LookbackOptionVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_extrema_without_outlier_filter() {
            vulnerabilities.push(LookbackOptionVulnerability {
                vulnerability_type: "Extrema Without Outlier Filter".to_string(),
                location: loc,
                severity: "Critical".to_string(),
                description: "Max/min tracking vulnerable to flash manipulation".to_string(),
                confidence: 0.90,
            });
        }
        vulnerabilities
    }
    fn has_extrema_without_outlier_filter(&self) -> Option<usize> {
        // GT/LT for max/min tracking
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x11 { // GT (for max)
                let mut has_outlier_check = false;
                for j in i.saturating_sub(10)..i {
                    // Outlier check: percentage bounds
                    if self.bytecode[j] == 0x02 && self.bytecode.get(j+3) == Some(&0x04) {
                        has_outlier_check = true;
                    }
                }
                if !has_outlier_check { return Some(i); }
            }
        }
        None
    }
}
