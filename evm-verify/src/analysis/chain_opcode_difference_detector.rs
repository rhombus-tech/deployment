use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainOpcodeDifferenceVulnerability {
    UnsupportedOpcode { description: String, location: usize, confidence: f32, opcode: String },
    DifferentBehavior { description: String, location: usize },
}

pub struct ChainOpcodeDifferenceDetector {
    bytecode: Vec<u8>,
}

impl ChainOpcodeDifferenceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ChainOpcodeDifferenceVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Opcodes that behave differently on L2s (zkEVMs, Optimism, Arbitrum)
        for i in 0..self.bytecode.len() {
            match self.bytecode[i] {
                0x44 => { // DIFFICULTY/PREVRANDAO - different on post-merge
                    vulnerabilities.push(ChainOpcodeDifferenceVulnerability::DifferentBehavior {
                        description: "DIFFICULTY opcode - returns PREVRANDAO post-merge, breaks on zkEVMs".to_string(),
                        location: i,
                    });
                },
                0xFF => { // SELFDESTRUCT - disabled on some L2s
                    vulnerabilities.push(ChainOpcodeDifferenceVulnerability::UnsupportedOpcode {
                        description: "SELFDESTRUCT not supported on zkSync, Starknet".to_string(),
                        location: i,
                        confidence: 0.85,
                        opcode: "SELFDESTRUCT".to_string(),
                    });
                },
                _ => {}
            }
        }
        
        vulnerabilities
    }
}
