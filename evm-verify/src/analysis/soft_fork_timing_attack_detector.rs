use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SoftForkTimingVulnerability {
    EIPActivationExploit { description: String, location: usize, confidence: f32 },
    BackwardCompatibilityBreak { description: String, location: usize, confidence: f32 },
}

pub struct SoftForkTimingAttackDetector {
    bytecode: Vec<u8>,
}

impl SoftForkTimingAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<SoftForkTimingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(75) {
            let section = &self.bytecode[i..std::cmp::min(i + 75, self.bytecode.len())];
            
            let has_new_opcode = section.contains(&0x5F) || section.contains(&0x5E);
            
            if has_new_opcode {
                let no_block_check = !section.windows(10).any(|w| {
                    w.contains(&0x43) && w.contains(&0x10)
                });
                
                if no_block_check {
                    vulnerabilities.push(SoftForkTimingVulnerability::EIPActivationExploit {
                        description: format!("EIP activation timing exploit at PC {}. Contract uses post-fork opcode without checking fork activated.", i),
                        location: i,
                        confidence: 0.89,
                    });
                }
            }
            
            let has_chainid_check = section.contains(&0x46);
            let has_prevrandao = section.contains(&0x44);
            
            if has_chainid_check || has_prevrandao {
                vulnerabilities.push(SoftForkTimingVulnerability::BackwardCompatibilityBreak {
                    description: format!("Backward compatibility break at PC {}. Contract behavior changes across forks.", i),
                    location: i,
                    confidence: 0.83,
                });
            }
        }
        
        vulnerabilities
    }
}
