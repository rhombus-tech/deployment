use serde::{Deserialize, Serialize};

/// Swaption: Option to enter interest rate swap
/// Attack: Game optimal exercise timing

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwaptionVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct SwaptionExerciseTimingDetector {
    bytecode: Vec<u8>,
}

impl SwaptionExerciseTimingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<SwaptionVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_exercise_frontrun() {
            vulnerabilities.push(SwaptionVulnerability {
                vulnerability_type: "Swaption Exercise Frontrun".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Exercise decision can be front-run based on rate moves".to_string(),
                confidence: 0.75,
            });
        }
        vulnerabilities
    }
    fn has_exercise_frontrun(&self) -> Option<usize> {
        // Exercise: rate comparison without slippage protection
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xfa { // Rate oracle
                for j in i+1..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // Rate comparison
                        let mut has_slippage = false;
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 { has_slippage = true; } // SUB tolerance
                        }
                        if !has_slippage { return Some(i); }
                    }
                }
            }
        }
        None
    }
}
