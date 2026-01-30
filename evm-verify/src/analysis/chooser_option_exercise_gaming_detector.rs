use serde::{Deserialize, Serialize};

/// Chooser Option: Choose call or put at future date
/// Attack: Front-run choice based on volatility

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChooserOptionVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ChooserOptionExerciseGamingDetector {
    bytecode: Vec<u8>,
}

impl ChooserOptionExerciseGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<ChooserOptionVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_choice_frontrun_risk() {
            vulnerabilities.push(ChooserOptionVulnerability {
                vulnerability_type: "Chooser Option Choice Frontrun".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Choice transaction can be front-run".to_string(),
                confidence: 0.75,
            });
        }
        vulnerabilities
    }
    fn has_choice_frontrun_risk(&self) -> Option<usize> {
        // Choice = state change based on user input
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x55 { // SSTORE (record choice)
                let mut has_commit_reveal = false;
                for j in i.saturating_sub(15)..i {
                    if self.bytecode[j] == 0x20 { // SHA3 (commit hash)
                        has_commit_reveal = true;
                    }
                }
                if !has_commit_reveal { return Some(i); }
            }
        }
        None
    }
}
