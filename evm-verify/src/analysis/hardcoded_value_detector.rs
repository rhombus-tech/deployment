use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HardcodedValueVulnerability {
    MagicNumber { description: String, location: usize, confidence: f32, value: String },
    HardcodedAddress { description: String, location: usize },
    HardcodedTime { description: String, location: usize },
}

pub struct HardcodedValueDetector {
    bytecode: Vec<u8>,
}

impl HardcodedValueDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<HardcodedValueVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Detect hardcoded addresses (PUSH20)
        for i in 0..self.bytecode.len().saturating_sub(21) {
            if self.bytecode[i] == 0x73 { // PUSH20 (address)
                vulnerabilities.push(HardcodedValueVulnerability::HardcodedAddress {
                    description: "Hardcoded address - may break on different networks/upgrades".to_string(),
                    location: i,
                });
            }
        }
        
        // Detect magic numbers (large constants without context)
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] >= 0x60 && self.bytecode[i] <= 0x7F { // PUSH1-PUSH32
                let push_size = (self.bytecode[i] - 0x5F) as usize;
                if push_size >= 4 && push_size <= 8 {
                    // Potentially magic number
                    if !self.is_common_constant(i, push_size) {
                        vulnerabilities.push(HardcodedValueVulnerability::MagicNumber {
                            description: "Magic number detected - should use named constant".to_string(),
                            location: i,
                            confidence: 0.60,
                            value: format!("{} bytes", push_size),
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_common_constant(&self, _location: usize, _size: usize) -> bool {
        // Could check for common values like 10^18, 100, etc.
        // For now, conservative approach
        false
    }
}
