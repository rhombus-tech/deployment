use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MaxTransactionBypassVulnerability {
    NoMaxTxCheck { description: String, location: usize, confidence: f32 },
    MaxTxBypassForOwner { description: String, location: usize },
    WeakMaxValidation { description: String, location: usize },
}

pub struct MaxTransactionBypassDetector {
    bytecode: Vec<u8>,
}

impl MaxTransactionBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MaxTransactionBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // transfer selector: 0xa9059cbb
        let transfer_selector = [0xa9, 0x05, 0x9c, 0xbb];
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i..].windows(4).any(|w| w == transfer_selector) {
                if self.has_amount_comparison(i, i + 100) {
                    if self.has_bypass_logic(i, i + 100) {
                        vulnerabilities.push(MaxTransactionBypassVulnerability::MaxTxBypassForOwner {
                            description: "Max transaction limit can be bypassed by owner/whitelist".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_amount_comparison(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // GT or LT comparison (max transaction check)
        self.bytecode[start..range_end].iter().any(|&b| b == 0x10 || b == 0x11)
    }
    
    fn has_bypass_logic(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // CALLER check (owner bypass)
        let has_caller = self.bytecode[start..range_end].iter().any(|&b| b == 0x33);
        let has_eq = self.bytecode[start..range_end].iter().any(|&b| b == 0x14);
        has_caller && has_eq
    }
}
