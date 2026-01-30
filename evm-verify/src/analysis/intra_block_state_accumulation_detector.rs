use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntraBlockVulnerability {
    StateAccumulationExploit { description: String, location: usize, confidence: f32 },
    TransactionSequenceManipulation { description: String, location: usize, confidence: f32 },
}

pub struct IntraBlockStateAccumulationDetector {
    bytecode: Vec<u8>,
}

impl IntraBlockStateAccumulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<IntraBlockVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(70) {
            let section = &self.bytecode[i..std::cmp::min(i + 70, self.bytecode.len())];
            
            // Pattern: State modified and read in same transaction without reset
            let has_cumulative_state = section.windows(15).any(|w| {
                w.contains(&0x54) && w.contains(&0x01) && w.contains(&0x55) // SLOAD + ADD + SSTORE
            });
            
            if has_cumulative_state {
                vulnerabilities.push(IntraBlockVulnerability::StateAccumulationExploit {
                    description: format!("Intra-block state accumulation at PC {}. Each tx in block modifies state for next tx. Attack: Bundle 100 txs in same block, each builds on previous state → amplify effect. Example: Reward pool updated by each claim → 100 claims in 1 block → final claim gets 100x accumulated state. Or: Price oracle updated incrementally → attacker bundles many updates → manipulates final price. Mitigation: Reset state per-tx, use snapshots, or limit per-block changes.", i),
                    location: i,
                    confidence: 0.85,
                });
            }
        }
        
        vulnerabilities
    }
}
