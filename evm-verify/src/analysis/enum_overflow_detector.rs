use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnumOverflowVulnerability {
    EnumBoundaryViolation { description: String, location: usize, confidence: f32 },
    UndefinedEnumValue { description: String, location: usize, confidence: f32 },
}

pub struct EnumOverflowDetector {
    bytecode: Vec<u8>,
}

impl EnumOverflowDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<EnumOverflowVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            let section = &self.bytecode[i..std::cmp::min(i + 50, self.bytecode.len())];
            
            // Pattern: Value assigned without bounds check (enum overflow)
            let has_storage_write = section.contains(&0x55); // SSTORE
            let has_unchecked_value = !section.windows(10).any(|w| {
                w.contains(&0x10) && w.contains(&0x57) // LT + JUMPI (bounds check)
            });
            
            if has_storage_write && has_unchecked_value {
                vulnerabilities.push(EnumOverflowVulnerability::EnumBoundaryViolation {
                    description: format!("Enum overflow at PC {}. Value stored without validating enum range. Attack: Set enum to invalid value (e.g., 255 when only 0-2 defined) → undefined behavior. Example: enum Status {{Pending, Active, Complete}} but attacker sets to 5 → bypasses all checks. Mitigation: Add require(value <= MAX_ENUM) before storage, or use Solidity 0.8+ enum safety.", i),
                    location: i,
                    confidence: 0.82,
                });
            }
        }
        
        vulnerabilities
    }
}
