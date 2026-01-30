use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MultiTxGasVulnerability {
    GasRefundManipulation { description: String, location: usize, confidence: f32 },
    CrossTxGasAccounting { description: String, location: usize, confidence: f32 },
}

pub struct MultiTxGasAccountingDetector {
    bytecode: Vec<u8>,
}

impl MultiTxGasAccountingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<MultiTxGasVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(70) {
            let section = &self.bytecode[i..std::cmp::min(i + 70, self.bytecode.len())];
            
            // Pattern: Storage operations that could be gamed for refunds
            let has_sstore = section.contains(&0x55); // SSTORE
            let has_sload = section.contains(&0x54); // SLOAD
            let has_gas_calc = section.contains(&0x5A); // GAS
            
            if has_sstore && has_sload && has_gas_calc {
                vulnerabilities.push(MultiTxGasVulnerability::GasRefundManipulation {
                    description: format!("Multi-tx gas accounting at PC {}. Gas refunds across transactions exploitable. Attack: Tx1 sets storage → Tx2 clears storage → net refund > cost. Example: SSTORE nonzero → zero gives 15k refund, only costs 5k → profit 10k gas. Across multiple txs: amplify refund. Or: Gas tokens (CHI, GST2) exploit this. Mitigation: EIP-3529 reduced refunds, but cross-tx patterns still exploitable.", i),
                    location: i,
                    confidence: 0.74,
                });
            }
        }
        
        vulnerabilities
    }
}
