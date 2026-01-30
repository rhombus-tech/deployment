use serde::{Deserialize, Serialize};

/// Snowball: Coupon accumulates if conditions met
/// Attack: Game path to maximize coupons

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnowballProductVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct SnowballProductPathManipulationDetector {
    bytecode: Vec<u8>,
}

impl SnowballProductPathManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<SnowballProductVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_coupon_path_gaming() {
            vulnerabilities.push(SnowballProductVulnerability {
                vulnerability_type: "Snowball Coupon Path Gaming".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Coupon accumulation path manipulatable".to_string(),
                confidence: 0.75,
            });
        }
        vulnerabilities
    }
    fn has_coupon_path_gaming(&self) -> Option<usize> {
        // Accumulated coupon: loop with conditional add
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x5b { // Loop
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x57 { // JUMPI (conditional)
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x01 { // ADD (accumulate coupon)
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }
        None
    }
}
