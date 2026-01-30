use serde::{Deserialize, Serialize};

/// Barrier Option: Knock-in/knock-out when price hits barrier
/// Attack: Manipulate price to trigger/avoid barrier

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BarrierOptionVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct BarrierOptionTriggerManipulationDetector {
    bytecode: Vec<u8>,
}

impl BarrierOptionTriggerManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<BarrierOptionVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_single_block_barrier_check() {
            vulnerabilities.push(BarrierOptionVulnerability {
                vulnerability_type: "Single Block Barrier Check".to_string(),
                location: loc,
                severity: "Critical".to_string(),
                description: "Barrier triggered by single-block price, flashloan attackable".to_string(),
                confidence: 0.90,
            });
        }
        vulnerabilities
    }
    fn has_single_block_barrier_check(&self) -> Option<usize> {
        // Price comparison without time averaging
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xfa { // Oracle price
                for j in i+1..i+20.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x11 || self.bytecode[j] == 0x10 { // GT/LT barrier check
                        // No TWAP if no timestamp operations
                        let mut has_twap = false;
                        for k in i..j {
                            if self.bytecode[k] == 0x42 { has_twap = true; }
                        }
                        if !has_twap { return Some(i); }
                    }
                }
            }
        }
        None
    }
}
