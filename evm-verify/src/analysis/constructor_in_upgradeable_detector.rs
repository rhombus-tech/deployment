use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConstructorInUpgradeableVulnerability {
    LogicInConstructor { description: String, location: usize, confidence: f32 },
    StateInitializedInConstructor { description: String, location: usize },
    NoInitializerFunction { description: String, location: usize },
}

pub struct ConstructorInUpgradeableDetector {
    bytecode: Vec<u8>,
}

impl ConstructorInUpgradeableDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ConstructorInUpgradeableVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.is_upgradeable_contract() {
            if self.has_constructor_logic() {
                if !self.has_initializer() {
                    vulnerabilities.push(ConstructorInUpgradeableVulnerability::LogicInConstructor {
                        description: "Upgradeable contract has logic in constructor instead of initializer - won't run in proxy context".to_string(),
                        location: 0,
                        confidence: 0.90,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_upgradeable_contract(&self) -> bool {
        self.bytecode.iter().any(|&b| b == 0xF4) || // DELEGATECALL
        self.bytecode.windows(4).any(|w| w == [0x36, 0x08, 0x94, 0xa1]) // EIP-1967
    }
    
    fn has_constructor_logic(&self) -> bool {
        // Constructor bytecode is before runtime bytecode
        // Look for CODECOPY pattern at start (indicates constructor)
        self.bytecode.len() > 100 && self.bytecode[0..100].contains(&0x39)
    }
    
    fn has_initializer(&self) -> bool {
        // initialize() selector: varies, but look for common patterns
        // Also check for "Initializable" pattern with storage flag
        let has_init_flag = self.bytecode.windows(2).any(|w| w[0] == 0x54 && w[1] == 0x15); // SLOAD ISZERO
        has_init_flag
    }
}
