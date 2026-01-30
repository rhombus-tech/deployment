use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TippingPointVulnerability {
    ThresholdCollapse { description: String, location: usize, confidence: f32 },
    CriticalMassAttack { description: String, location: usize, confidence: f32 },
}

pub struct TippingPointAttackDetector {
    bytecode: Vec<u8>,
}

impl TippingPointAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<TippingPointVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(70) {
            let section = &self.bytecode[i..std::cmp::min(i + 70, self.bytecode.len())];
            
            // Pattern: Threshold check that triggers cascade
            let has_threshold = section.windows(12).any(|w| {
                w.contains(&0x54) && w.contains(&0x10) && w.contains(&0x57) // SLOAD + LT + JUMPI
            });
            
            let has_state_change = section.contains(&0x55); // SSTORE
            
            if has_threshold && has_state_change {
                vulnerabilities.push(TippingPointVulnerability::ThresholdCollapse {
                    description: format!("Tipping point at PC {}. N-1 participants: safe. N participants: systemic collapse. Attack: Be the Nth attacker who triggers cascade. Example: Bank run at 51% withdrawal → everyone rushes → collapse. Or: Stablecoin depeg once reserves < 90% → panic sell → death spiral. Critical mass: Below threshold stable, above threshold unstable. Mitigation: Design for graceful degradation, not cliff edges. Use continuous functions not step functions.", i),
                    location: i,
                    confidence: 0.83,
                });
            }
        }
        
        vulnerabilities
    }
}
