use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EthSendFailureVulnerability {
    UsingTransfer { description: String, location: usize, confidence: f32 },
    UsingSend { description: String, location: usize },
    Gas2300Limit { description: String, location: usize, confidence: f32 },
}

pub struct EthSendFailureDetector {
    bytecode: Vec<u8>,
}

impl EthSendFailureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EthSendFailureVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xF1 { // CALL
                if self.has_2300_gas_limit(i) {
                    vulnerabilities.push(EthSendFailureVulnerability::Gas2300Limit {
                        description: "ETH transfer with 2300 gas limit - will fail if recipient has logic".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_2300_gas_limit(&self, call_location: usize) -> bool {
        let start = call_location.saturating_sub(10);
        // 2300 = 0x08FC in hex
        self.bytecode[start..call_location].windows(3).any(|w| {
            w[0] == 0x61 && w[1] == 0x08 && w[2] == 0xFC
        })
    }
}
