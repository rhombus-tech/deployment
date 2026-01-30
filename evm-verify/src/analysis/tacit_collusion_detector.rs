use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TacitCollusionVulnerability {
    FocalPointCollusion { description: String, location: usize, confidence: f32 },
    IteratedGameCollusion { description: String, location: usize, confidence: f32 },
}

pub struct TacitCollusionDetector {
    bytecode: Vec<u8>,
}

impl TacitCollusionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<TacitCollusionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(65) {
            let section = &self.bytecode[i..std::cmp::min(i + 65, self.bytecode.len())];
            
            // Pattern: Reward distribution where coordination is Nash equilibrium
            let has_reward = section.windows(15).any(|w| {
                w.contains(&0x54) && w.contains(&0x04) && w.contains(&0x02) // SLOAD + DIV + MUL
            });
            
            let has_multi_participant = section.windows(10).any(|w| {
                w.contains(&0x33) // Multiple CALLER checks
            });
            
            if has_reward && has_multi_participant {
                vulnerabilities.push(TacitCollusionVulnerability::FocalPointCollusion {
                    description: format!("Tacit collusion at PC {}. No communication needed, coordination is dominant strategy. Attack: All actors independently choose same strategy → collude without talking. Example: Oracle network where reporting wrong price is profitable if others do too → everyone reports wrong. Or: Validators censor same tx without coordination (obvious target). Game theory: Schelling point = everyone gravitates to obvious choice. Mitigation: Randomize who acts first, penalize correlation, or require commitment schemes.", i),
                    location: i,
                    confidence: 0.77,
                });
            }
            
            // Pattern: Repeated game where cooperation emerges
            let has_loop = section.windows(8).any(|w| {
                w.contains(&0x56) || w.contains(&0x57) // JUMP or JUMPI (loop)
            });
            
            if has_reward && has_loop {
                vulnerabilities.push(TacitCollusionVulnerability::IteratedGameCollusion {
                    description: format!("Iterated game collusion at PC {}. Repeated interactions enable tit-for-tat cooperation. Attack: In repeated game, cooperate (collude) to maximize joint profit. Example: MEV searchers in repeated blocks learn to not compete → split profits. Or: Validators rotate block proposals → don't steal each other's MEV. Folk theorem: Any outcome between minmax and Pareto optimal sustainable. Mitigation: Shuffle participants, limit repetition, or add noise to outcomes.", i),
                    location: i,
                    confidence: 0.73,
                });
            }
        }
        
        vulnerabilities
    }
}
