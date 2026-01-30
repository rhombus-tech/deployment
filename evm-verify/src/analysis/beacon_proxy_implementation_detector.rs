use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BeaconProxyImplementationVulnerability {
    ImplementationNotContract { description: String, location: usize, confidence: f32 },
    NoBeaconValidation { description: String, location: usize },
    BeaconUpgradeableByAnyone { description: String, location: usize },
}

pub struct BeaconProxyImplementationDetector {
    bytecode: Vec<u8>,
}

impl BeaconProxyImplementationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BeaconProxyImplementationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.loads_implementation_from_beacon(i, i + 100) {
                if !self.validates_implementation_is_contract(i, i + 100) {
                    vulnerabilities.push(BeaconProxyImplementationVulnerability::ImplementationNotContract {
                        description: "Beacon implementation loaded without EXTCODESIZE check - can point to EOA".to_string(),
                        location: i,
                        confidence: 0.90,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn loads_implementation_from_beacon(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // implementation() selector: 0x5c60da1b
        self.bytecode[start..range_end]
            .windows(4)
            .any(|w| w == [0x5c, 0x60, 0xda, 0x1b])
    }
    
    fn validates_implementation_is_contract(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // EXTCODESIZE check
        self.bytecode[start..range_end].iter().any(|&b| b == 0x3B) // EXTCODESIZE
    }
}
