use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CalldataExpansionDosVulnerability {
    UnboundedCalldataLoop { description: String, location: usize },
    CalldataCopyBomb { description: String, location: usize, confidence: f32 },
    NestedCalldataExpansion { description: String, location: usize },
}

pub struct CalldataExpansionDosDetector {
    bytecode: Vec<u8>,
}

impl CalldataExpansionDosDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CalldataExpansionDosVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.has_calldata_loop(i, i + 80) {
                if !self.has_iteration_limit(i, i + 80) {
                    vulnerabilities.push(CalldataExpansionDosVulnerability::UnboundedCalldataLoop {
                        description: "Unbounded loop over calldata - attacker can provide huge array".to_string(),
                        location: i,
                    });
                }
            }
            
            if self.is_calldata_copy(i) && !self.has_size_validation(i, i + 40) {
                vulnerabilities.push(CalldataExpansionDosVulnerability::CalldataCopyBomb {
                    description: "CALLDATACOPY without size validation - DoS via large calldata".to_string(),
                    location: i,
                    confidence: 0.85,
                });
            }
        }
        
        vulnerabilities
    }
    
    fn has_calldata_loop(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        let has_calldataload = self.bytecode[start..range_end].iter().any(|&b| b == 0x35);
        let has_jumpi = self.bytecode[start..range_end].iter().any(|&b| b == 0x57);
        has_calldataload && has_jumpi
    }
    
    fn has_iteration_limit(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // Check for counter limit
        self.bytecode[start..range_end].windows(2).any(|w| {
            (w[0] == 0x10 || w[0] == 0x11) && w[1] == 0xFD // comparison + REVERT
        })
    }
    
    fn is_calldata_copy(&self, location: usize) -> bool {
        self.bytecode.get(location) == Some(&0x37) // CALLDATACOPY
    }
    
    fn has_size_validation(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        self.bytecode[start..range_end].iter().any(|&b| b == 0x36) // CALLDATASIZE
    }
}
