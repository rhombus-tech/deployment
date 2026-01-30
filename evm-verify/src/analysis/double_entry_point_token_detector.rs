use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DoubleEntryPointTokenVulnerability {
    MultipleTokenAddresses { description: String, location: usize, confidence: f32 },
    LegacyTokenNotHandled { description: String, location: usize },
    TransferFromBothAddresses { description: String, location: usize },
}

pub struct DoubleEntryPointTokenDetector {
    bytecode: Vec<u8>,
}

impl DoubleEntryPointTokenDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DoubleEntryPointTokenVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Double entry point: token accessible via multiple addresses (e.g., old TUSD)
        if self.has_multiple_token_transfers() && !self.validates_single_token_entry() {
            vulnerabilities.push(DoubleEntryPointTokenVulnerability::MultipleTokenAddresses {
                description: "Multiple token transfer paths without single entry validation - double entry risk".to_string(),
                location: 0,
                confidence: 0.75,
            });
        }
        
        vulnerabilities
    }
    
    fn has_multiple_token_transfers(&self) -> bool {
        // Count transferFrom calls
        let transfer_count = self.bytecode.windows(4)
            .filter(|w| *w == [0x23, 0xb8, 0x72, 0xdd])
            .count();
        
        transfer_count >= 2
    }
    
    fn validates_single_token_entry(&self) -> bool {
        // Check for address equality validation
        self.bytecode.windows(2).any(|w| w[0] == 0x14 && w[1] == 0xFD) // EQ + REVERT
    }
}
