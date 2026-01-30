use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpotPriceManipulationVulnerability {
    UsingReservesDirectly { description: String, location: usize, confidence: f32 },
    NoTwapOracle { description: String, location: usize },
}

pub struct SpotPriceManipulationDetector {
    bytecode: Vec<u8>,
}

impl SpotPriceManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SpotPriceManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        let get_reserves = [0x09, 0x02, 0xf1, 0xac]; // getReserves()
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.bytecode[i..].windows(4).any(|w| w == get_reserves) {
                if self.uses_reserves_for_price(i, i + 80) && !self.has_twap_protection(i, i + 80) {
                    vulnerabilities.push(SpotPriceManipulationVulnerability::UsingReservesDirectly {
                        description: "Using spot reserves for price - flash loan manipulation".to_string(),
                        location: i,
                        confidence: 0.90,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn uses_reserves_for_price(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        self.bytecode[start..range_end].iter().any(|&b| b == 0x04) // DIV
    }
    
    fn has_twap_protection(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        let has_timestamp = self.bytecode[start..range_end].iter().any(|&b| b == 0x42);
        let sload_count = self.bytecode[start..range_end].iter().filter(|&&b| b == 0x54).count();
        has_timestamp && sload_count >= 2
    }
}
