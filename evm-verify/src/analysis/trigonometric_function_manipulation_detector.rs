use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrigonometricVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TrigonometricFunctionManipulationDetector {
    bytecode: Vec<u8>,
}

impl TrigonometricFunctionManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<TrigonometricVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_cordic_without_bounds() {
            vulnerabilities.push(TrigonometricVulnerability {
                vulnerability_type: "CORDIC Approximation Without Bounds".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Trig approximation lacks iteration/precision bounds".to_string(),
                confidence: 0.75,
            });
        }
        vulnerabilities
    }
    fn has_cordic_without_bounds(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x5b { // Loop for CORDIC
                let mut has_shift = false;
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x1b || self.bytecode[j] == 0x1c { // SHL/SHR
                        has_shift = true;
                    }
                }
                if has_shift { return Some(i); }
            }
        }
        None
    }
}
