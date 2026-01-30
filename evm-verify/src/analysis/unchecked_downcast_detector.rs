use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UncheckedDowncastVulnerability {
    Uint256ToUint128 { description: String, location: usize, confidence: f32 },
    Uint256ToUint64 { description: String, location: usize, confidence: f32 },
    UncheckedTypeCast { description: String, location: usize },
}

pub struct UncheckedDowncastDetector {
    bytecode: Vec<u8>,
}

impl UncheckedDowncastDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<UncheckedDowncastVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x16 { // AND opcode (used for downcasting)
                if self.is_uint128_mask(i) && !self.has_overflow_check_before(i) {
                    vulnerabilities.push(UncheckedDowncastVulnerability::Uint256ToUint128 {
                        description: "Unchecked downcast uint256→uint128 - truncation overflow".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
                
                if self.is_uint64_mask(i) && !self.has_overflow_check_before(i) {
                    vulnerabilities.push(UncheckedDowncastVulnerability::Uint256ToUint64 {
                        description: "Unchecked downcast uint256→uint64 - truncation overflow".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_uint128_mask(&self, and_location: usize) -> bool {
        let start = and_location.saturating_sub(20);
        self.bytecode[start..and_location].windows(17).any(|w| {
            w[0] == 0x70 && w[1..17].iter().all(|&b| b == 0xFF)
        })
    }
    
    fn is_uint64_mask(&self, and_location: usize) -> bool {
        let start = and_location.saturating_sub(12);
        self.bytecode[start..and_location].windows(9).any(|w| {
            w[0] == 0x68 && w[1..9].iter().all(|&b| b == 0xFF)
        })
    }
    
    fn has_overflow_check_before(&self, and_location: usize) -> bool {
        let start = and_location.saturating_sub(30);
        self.bytecode[start..and_location].windows(3).any(|w| {
            (w[0] == 0x10 || w[0] == 0x11) && w[2] == 0xFD
        })
    }
}
