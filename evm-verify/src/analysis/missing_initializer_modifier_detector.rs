use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MissingInitializerModifierVulnerability {
    InitializeCallableMultipleTimes { description: String, location: usize, confidence: f32 },
    NoInitializedFlag { description: String, location: usize },
    InitializerNotProtected { description: String, location: usize },
}

pub struct MissingInitializerModifierDetector {
    bytecode: Vec<u8>,
}

impl MissingInitializerModifierDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MissingInitializerModifierVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.is_upgradeable_contract() {
            for i in 0..self.bytecode.len().saturating_sub(80) {
                if self.looks_like_initializer(i) {
                    if !self.has_initialized_check(i, i + 80) {
                        vulnerabilities.push(MissingInitializerModifierVulnerability::InitializeCallableMultipleTimes {
                            description: "initialize() function without initialized flag check - can be called multiple times".to_string(),
                            location: i,
                            confidence: 0.85,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_upgradeable_contract(&self) -> bool {
        self.bytecode.iter().any(|&b| b == 0xF4)
    }
    
    fn looks_like_initializer(&self, location: usize) -> bool {
        // Initialize function typically has CALLDATALOAD early and state changes
        let range_end = (location + 60).min(self.bytecode.len());
        let has_calldataload = self.bytecode[location..range_end].iter().any(|&b| b == 0x35);
        let has_sstore = self.bytecode[location..range_end].iter().any(|&b| b == 0x55);
        has_calldataload && has_sstore
    }
    
    fn has_initialized_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Pattern: SLOAD (check initialized flag) → ISZERO → JUMPI/REVERT
        let positions: Vec<_> = self.bytecode[start..range_end]
            .iter()
            .enumerate()
            .filter(|(_, &b)| b == 0x54)
            .map(|(i, _)| i)
            .collect();
        
        for pos in positions {
            let check_end = (pos + 10).min(range_end - start);
            if self.bytecode[start + pos..start + check_end].contains(&0x15) &&
               self.bytecode[start + pos..start + check_end].contains(&0xFD) {
                return true;
            }
        }
        
        false
    }
}
