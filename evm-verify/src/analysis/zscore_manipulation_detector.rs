use serde::{Deserialize, Serialize};

/// Z-Score: (X - μ) / σ
/// Used for outlier detection and risk scoring
/// Can be gamed by manipulating mean/stddev

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZScoreVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ZScoreManipulationDetector {
    bytecode: Vec<u8>,
}

impl ZScoreManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<ZScoreVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_zscore_without_sample_size_check() {
            vulnerabilities.push(ZScoreVulnerability {
                vulnerability_type: "Z-Score Without Sample Size Validation".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Z-score calculated on insufficient sample size".to_string(),
                confidence: 0.75,
            });
        }
        vulnerabilities
    }
    fn has_zscore_without_sample_size_check(&self) -> Option<usize> {
        // Pattern: (X - mean) / stddev without n check
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x03 && // SUB (X - mean)
               self.bytecode.get(i+3) == Some(&0x04) { // DIV by stddev
                // Check for sample size validation
                let mut has_sample_check = false;
                for j in i.saturating_sub(10)..i {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {
                        has_sample_check = true;
                    }
                }
                if !has_sample_check {
                    return Some(i);
                }
            }
        }
        None
    }
}
