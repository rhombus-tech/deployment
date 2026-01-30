use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockBoundaryVulnerability {
    TransactionBoundaryRace { description: String, location: usize, confidence: f32 },
    BlockNumberDependency { description: String, location: usize, confidence: f32 },
}

pub struct BlockBoundaryRaceDetector {
    bytecode: Vec<u8>,
}

impl BlockBoundaryRaceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<BlockBoundaryVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(60) {
            let section = &self.bytecode[i..std::cmp::min(i + 60, self.bytecode.len())];
            
            // Pattern: State change dependent on block.number equality
            let has_block_number = section.contains(&0x43); // NUMBER
            let has_equality_check = section.windows(3).any(|w| w.contains(&0x14)); // EQ
            let has_state_change = section.windows(3).any(|w| w.contains(&0x55)); // SSTORE
            
            if has_block_number && has_equality_check && has_state_change {
                vulnerabilities.push(BlockBoundaryVulnerability::TransactionBoundaryRace {
                    description: format!("Block boundary race at PC {}. Transaction landing in block N vs N+1 produces different outcome. Attack: Tx submitted targeting block N, miners include in N+1 → unexpected state. Example: Reward distribution at exact block, early claim vs late claim. Mitigation: Use block ranges not exact numbers, or block.timestamp with buffer.", i),
                    location: i,
                    confidence: 0.84,
                });
            }
            
            // Pattern: Critical operation depends on block.number modulo
            let has_modulo = section.windows(2).any(|w| w.contains(&0x06)); // MOD
            if has_block_number && has_modulo {
                vulnerabilities.push(BlockBoundaryVulnerability::BlockNumberDependency {
                    description: format!("Block number dependency at PC {}. Logic uses block.number % N → behavior differs at boundaries. Example: block.number % 100 == 0 for rewards → race to be in that exact block. Mitigation: Use deterministic ordering not modulo arithmetic.", i),
                    location: i,
                    confidence: 0.78,
                });
            }
        }
        
        vulnerabilities
    }
}
