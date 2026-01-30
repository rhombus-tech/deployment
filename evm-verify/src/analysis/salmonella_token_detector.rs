use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SalmonellaTokenVulnerability {
    MevBotPoison { description: String, location: usize, confidence: f32 },
    FakeBalanceReturn { description: String, location: usize },
}

pub struct SalmonellaTokenDetector {
    bytecode: Vec<u8>,
}

impl SalmonellaTokenDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SalmonellaTokenVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // balanceOf selector: 0x70a08231
        let balance_of = [0x70, 0xa0, 0x82, 0x31];
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.bytecode[i..].windows(4).any(|w| w == balance_of) {
                // Salmonella tokens return fake high balances to poison MEV bots
                if self.returns_constant_high_value(i, i + 80) {
                    vulnerabilities.push(SalmonellaTokenVulnerability::FakeBalanceReturn {
                        description: "balanceOf returns constant high value - MEV bot poison risk".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn returns_constant_high_value(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Look for large constant PUSH followed by RETURN
        for i in start..range_end.saturating_sub(10) {
            if self.bytecode[i] >= 0x60 && self.bytecode[i] <= 0x7F { // PUSH1-PUSH32
                let push_size = (self.bytecode[i] - 0x5F) as usize;
                if push_size >= 8 { // Large value (>=8 bytes)
                    return true;
                }
            }
        }
        false
    }
}
