use serde::{Deserialize, Serialize};

/// Timestamp Quantization: Block timestamps in discrete buckets
/// Attack: Game transactions to fall into favorable time buckets

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampQuantizationVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TimestampQuantizationDetector {
    bytecode: Vec<u8>,
}

impl TimestampQuantizationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<TimestampQuantizationVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_timestamp_bucketing() {
            vulnerabilities.push(TimestampQuantizationVulnerability {
                vulnerability_type: "Timestamp Bucketing Without Randomization".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Timestamp divided into discrete buckets, gameable".to_string(),
                confidence: 0.80,
            });
        }
        vulnerabilities
    }
    fn has_timestamp_bucketing(&self) -> Option<usize> {
        // Timestamp DIV/MOD for bucketing
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                for j in i+1..i+10.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x04 || self.bytecode[j] == 0x06 { // DIV/MOD
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
