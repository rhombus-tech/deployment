use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ERC4337InitCodeVulnerability {
    InitCodeFrontRunning { description: String, location: usize, confidence: f32 },
    PredictableWalletAddress { description: String, location: usize, confidence: f32 },
}

pub struct ERC4337InitCodeFrontrunDetector {
    bytecode: Vec<u8>,
}

impl ERC4337InitCodeFrontrunDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<ERC4337InitCodeVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(60) {
            let section = &self.bytecode[i..std::cmp::min(i + 60, self.bytecode.len())];
            let has_create2 = section.contains(&0xF5); // CREATE2
            let no_nonce_salt = !section.contains(&0x42) && !section.contains(&0x33);
            if has_create2 && no_nonce_salt {
                vulnerabilities.push(ERC4337InitCodeVulnerability::InitCodeFrontRunning {
                    description: format!("ERC-4337 wallet deployment at PC {} uses CREATE2 without nonce/timestamp salt. Attack: Monitor mempool for initCode → front-run with same initCode → deploy to same address first → steal intended funds. Add timestamp or user-specific nonce to salt.", i),
                    location: i,
                    confidence: 0.92,
                });
            }
        }
        vulnerabilities
    }
}
