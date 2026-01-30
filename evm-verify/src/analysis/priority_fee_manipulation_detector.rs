use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PriorityFeeManipulationVulnerability {
    GasAuctionManipulation {
        description: String,
        location: usize,
        confidence: f32,
    },
    BaseFeeDependent {
        description: String,
        location: usize,
    },
    PriorityFeeOrdering {
        description: String,
        location: usize,
    },
}

pub struct PriorityFeeManipulationDetector {
    bytecode: Vec<u8>,
}

impl PriorityFeeManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PriorityFeeManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.uses_gas_price_in_logic(i) {
                let affects_ordering = self.gas_affects_execution_order(i, i + 100);
                
                if affects_ordering {
                    vulnerabilities.push(PriorityFeeManipulationVulnerability::GasAuctionManipulation {
                        description: "Gas price affects execution order - manipulation risk".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
            }
            
            if self.uses_basefee(i) {
                vulnerabilities.push(PriorityFeeManipulationVulnerability::BaseFeeDependent {
                    description: "Logic depends on BASEFEE which can be manipulated".to_string(),
                    location: i,
                });
            }
        }
        
        vulnerabilities
    }
    
    fn uses_gas_price_in_logic(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        self.bytecode[location..location + 20].iter().any(|&b| b == 0x3a) // GASPRICE
    }
    
    fn gas_affects_execution_order(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        self.bytecode[start..range_end].windows(3).any(|w| {
            w[0] == 0x3a && // GASPRICE
            (w[1] == 0x10 || w[1] == 0x11) // LT or GT
        })
    }
    
    fn uses_basefee(&self, location: usize) -> bool {
        if location + 15 > self.bytecode.len() {
            return false;
        }
        
        self.bytecode[location..location + 15].iter().any(|&b| b == 0x48) // BASEFEE
    }
}
