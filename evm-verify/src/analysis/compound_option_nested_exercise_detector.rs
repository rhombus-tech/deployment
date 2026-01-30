use serde::{Deserialize, Serialize};

/// Compound Option: Option on an option
/// Attack: Game nested exercise decisions

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundOptionVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CompoundOptionNestedExerciseDetector {
    bytecode: Vec<u8>,
}

impl CompoundOptionNestedExerciseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<CompoundOptionVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_nested_exercise_race() {
            vulnerabilities.push(CompoundOptionVulnerability {
                vulnerability_type: "Nested Exercise Race Condition".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Compound option exercise order manipulatable".to_string(),
                confidence: 0.70,
            });
        }
        vulnerabilities
    }
    fn has_nested_exercise_race(&self) -> Option<usize> {
        // Multiple exercise checks
        for i in 0..self.bytecode.len().saturating_sub(40) {
            let mut exercise_checks = 0;
            for j in i..i+35.min(self.bytecode.len()) {
                // Exercise check: timestamp + price comparison
                if self.bytecode[j] == 0x42 && self.bytecode.get(j+5) == Some(&0x10) {
                    exercise_checks += 1;
                }
            }
            if exercise_checks >= 2 { return Some(i); }
        }
        None
    }
}
