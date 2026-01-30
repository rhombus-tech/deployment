use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlacklistBypassVulnerability {
    TransferToContract { description: String, location: usize, confidence: f32 },
    DelegateCallBypass { description: String, location: usize },
    ApproveBypass { description: String, location: usize },
}

pub struct BlacklistBypassDetector {
    bytecode: Vec<u8>,
}

impl BlacklistBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BlacklistBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // transfer selector: 0xa9059cbb
        let transfer_selector = [0xa9, 0x05, 0x9c, 0xbb];
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i..].windows(4).any(|w| w == transfer_selector) {
                if self.has_blacklist_check(i, i + 100) {
                    if self.has_delegatecall_nearby(i, i + 100) {
                        vulnerabilities.push(BlacklistBypassVulnerability::DelegateCallBypass {
                            description: "Blacklist can be bypassed via delegatecall to non-blacklisted contract".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_blacklist_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // SLOAD + comparison pattern
        let has_sload = self.bytecode[start..range_end].iter().any(|&b| b == 0x54);
        let has_eq = self.bytecode[start..range_end].iter().any(|&b| b == 0x14);
        has_sload && has_eq
    }
    
    fn has_delegatecall_nearby(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        self.bytecode[start..range_end].iter().any(|&b| b == 0xF4)
    }
}
