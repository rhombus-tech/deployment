use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SalamiSlicingVulnerability {
    MicroTheftAccumulation { description: String, location: usize, confidence: f32 },
    RoundingExploitation { description: String, location: usize, confidence: f32 },
}

pub struct SalamiSlicingDetector {
    bytecode: Vec<u8>,
}

impl SalamiSlicingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<SalamiSlicingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(60) {
            let section = &self.bytecode[i..std::cmp::min(i + 60, self.bytecode.len())];
            
            // Pattern: Rounding down with no dust accumulation
            let has_division = section.contains(&0x04); // DIV
            let has_transfer = section.windows(10).any(|w| w.contains(&0xF1)); // CALL
            let no_dust_tracking = !section.windows(15).any(|w| {
                w.contains(&0x03) && w.contains(&0x55) // SUB + SSTORE (track remainder)
            });
            
            if has_division && has_transfer && no_dust_tracking {
                vulnerabilities.push(SalamiSlicingVulnerability::MicroTheftAccumulation {
                    description: format!("Salami slicing at PC {}. Rounding errors not tracked → attacker steals dust. Attack: Trigger 1000 operations each losing 1 wei to rounding → steal 1000 wei. Example: Reward distribution rounds down → dust stays in contract → attacker claims all dust. Or: Fee calculation loses 0.0001% per tx → attacker makes 10000 txs → steals 1%. Each theft imperceptible, total significant. Mitigation: Track and redistribute dust, or use higher precision.", i),
                    location: i,
                    confidence: 0.86,
                });
            }
        }
        
        vulnerabilities
    }
}
