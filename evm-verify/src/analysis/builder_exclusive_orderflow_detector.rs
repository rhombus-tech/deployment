use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BuilderExclusiveOrderflowVulnerability {
    ExclusiveOrderflowRisk {
        description: String,
        location: usize,
        confidence: f32,
    },
    BuilderCentralization {
        description: String,
        location: usize,
    },
}

pub struct BuilderExclusiveOrderflowDetector {
    bytecode: Vec<u8>,
}

impl BuilderExclusiveOrderflowDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BuilderExclusiveOrderflowVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.has_builder_address_check(i) {
                let is_exclusive = self.enforces_exclusive_builder(i, i + 100);
                
                if is_exclusive {
                    vulnerabilities.push(BuilderExclusiveOrderflowVulnerability::ExclusiveOrderflowRisk {
                        description: "Transaction restricted to specific builder - censorship risk".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_builder_address_check(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        self.bytecode[location..location + 30].iter().any(|&b| b == 0x41)
    }
    
    fn enforces_exclusive_builder(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        self.bytecode[start..range_end].windows(3).any(|w| {
            w[0] == 0x41 && w[1] == 0x14 && w[2] == 0xfd
        })
    }
}
