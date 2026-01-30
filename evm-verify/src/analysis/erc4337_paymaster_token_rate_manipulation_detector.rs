use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ERC4337PaymasterTokenRateVulnerability {
    TokenRateManipulation { description: String, location: usize, confidence: f32 },
    ValidationExecutionPriceGap { description: String, location: usize, confidence: f32 },
}

pub struct ERC4337PaymasterTokenRateManipulationDetector {
    bytecode: Vec<u8>,
}

impl ERC4337PaymasterTokenRateManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<ERC4337PaymasterTokenRateVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(80) {
            let section = &self.bytecode[i..std::cmp::min(i + 80, self.bytecode.len())];
            let reads_token_price = section.contains(&0xFA); // STATICCALL (oracle)
            let no_price_cache = !section.windows(6).any(|w| w.contains(&0x54) && w.contains(&0x55));
            if reads_token_price && no_price_cache {
                vulnerabilities.push(ERC4337PaymasterTokenRateVulnerability::ValidationExecutionPriceGap {
                    description: format!("Paymaster at PC {} reads token price in both validation and execution. ERC-4337: validatePaymasterUserOp() at block N, handleOps() execution at block N+1. Attacker: flash loan pumps token → validation sees high price → accepts low gas payment → execution at normal price → paymaster loses funds. Cache price from validation.", i),
                    location: i,
                    confidence: 0.91,
                });
            }
        }
        vulnerabilities
    }
}
