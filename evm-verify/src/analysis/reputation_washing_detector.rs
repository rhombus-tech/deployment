use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReputationWashingVulnerability {
    ReputationTransfer { description: String, location: usize, confidence: f32 },
    HistoryErasure { description: String, location: usize, confidence: f32 },
}

pub struct ReputationWashingDetector {
    bytecode: Vec<u8>,
}

impl ReputationWashingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<ReputationWashingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(65) {
            let section = &self.bytecode[i..std::cmp::min(i + 65, self.bytecode.len())];
            
            // Pattern: Reputation/score can be transferred
            let has_reputation_read = section.windows(10).any(|w| {
                w.contains(&0x54) && w.contains(&0x33) // SLOAD with CALLER
            });
            
            let has_transfer_logic = section.windows(15).any(|w| {
                w.contains(&0x55) && w.contains(&0x35) // SSTORE with CALLDATALOAD (recipient)
            });
            
            if has_reputation_read && has_transfer_logic {
                vulnerabilities.push(ReputationWashingVulnerability::ReputationTransfer {
                    description: format!("Reputation washing at PC {}. Reputation can be moved between addresses. Attack: Build good reputation on address A → transfer to address B → A can misbehave, B has clean reputation. Example: Tornado Cash deposits from sanctioned address → mix → withdraw to clean address → reputation laundered. Or: Bad actor on protocol → create new address → transfer reputation tokens → clean slate. Mitigation: Soulbound reputation (non-transferable), or track full lineage of reputation transfers.", i),
                    location: i,
                    confidence: 0.78,
                });
            }
        }
        
        vulnerabilities
    }
}
