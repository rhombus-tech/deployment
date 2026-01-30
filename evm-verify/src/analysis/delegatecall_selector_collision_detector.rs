use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DelegatecallSelectorCollisionVulnerability {
    SelectorClash { description: String, location: usize, selector: Vec<u8>, confidence: f32 },
    UncheckedDelegatecall { description: String, location: usize },
    StorageCollisionRisk { description: String, location: usize },
}

pub struct DelegatecallSelectorCollisionDetector {
    bytecode: Vec<u8>,
}

impl DelegatecallSelectorCollisionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DelegatecallSelectorCollisionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.bytecode[i] == 0xF4 { // DELEGATECALL
                if !self.validates_selector_before_delegatecall(i) {
                    vulnerabilities.push(DelegatecallSelectorCollisionVulnerability::UncheckedDelegatecall {
                        description: "DELEGATECALL without selector validation - collision risk".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn validates_selector_before_delegatecall(&self, location: usize) -> bool {
        let start = location.saturating_sub(30);
        
        // Should validate selector before delegatecall
        self.bytecode[start..location]
            .windows(2)
            .any(|w| w[0] == 0x14 && w[1] == 0xFD) // EQ + REVERT
    }
}
