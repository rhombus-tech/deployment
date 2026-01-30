use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeflationaryTokenVulnerability {
    TransferAmountNotValidated { description: String, location: usize, confidence: f32 },
    BalanceChangeNotMeasured { description: String, location: usize },
    FeeOnTransferNotHandled { description: String, location: usize },
}

pub struct DeflationaryTokenDetector {
    bytecode: Vec<u8>,
}

impl DeflationaryTokenDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DeflationaryTokenVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.is_token_transfer(i) {
                if !self.measures_actual_balance_change(i, i + 150) {
                    vulnerabilities.push(DeflationaryTokenVulnerability::BalanceChangeNotMeasured {
                        description: "Token transfer without measuring actual balance change - fee-on-transfer risk".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_token_transfer(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        // transferFrom: 0x23b872dd, transfer: 0xa9059cbb
        self.bytecode[location..location + 20].windows(4).any(|w| {
            w == [0x23, 0xb8, 0x72, 0xdd] || w == [0xa9, 0x05, 0x9c, 0xbb]
        })
    }
    
    fn measures_actual_balance_change(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Pattern: balanceOf before + balanceOf after + SUB
        let balance_of_count = self.bytecode[start..range_end]
            .windows(4)
            .filter(|w| *w == [0x70, 0xa0, 0x82, 0x31])
            .count();
        
        let has_sub = self.bytecode[start..range_end].iter().any(|&b| b == 0x03);
        
        // Need 2 balanceOf calls and SUB to measure actual change
        balance_of_count >= 2 && has_sub
    }
}
