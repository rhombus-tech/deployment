use serde::{Deserialize, Serialize};

/// Yield Curve Interpolation: Linear, cubic spline, Nelson-Siegel
/// Interpolation between known rates can be gamed

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YieldCurveVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct YieldCurveInterpolationDetector {
    bytecode: Vec<u8>,
}

impl YieldCurveInterpolationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<YieldCurveVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_linear_interpolation_gaming() {
            vulnerabilities.push(YieldCurveVulnerability {
                vulnerability_type: "Yield Curve Linear Interpolation Gaming".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Linear interpolation between sparse points gameable".to_string(),
                confidence: 0.70,
            });
        }
        vulnerabilities
    }
    fn has_linear_interpolation_gaming(&self) -> Option<usize> {
        // Pattern: Weighted sum for interpolation
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x02 && // MUL (weight)
               self.bytecode.get(i+3) == Some(&0x01) && // ADD
               self.bytecode.get(i+6) == Some(&0x02) { // MUL again
                return Some(i);
            }
        }
        None
    }
}
