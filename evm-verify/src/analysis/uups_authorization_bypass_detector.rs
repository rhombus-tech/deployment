use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UupsAuthorizationBypassVulnerability {
    NoAuthorizationCheck { description: String, location: usize, confidence: f32 },
    WeakAuthorization { description: String, location: usize },
    ProxiableUUIDNotValidated { description: String, location: usize },
}

pub struct UupsAuthorizationBypassDetector {
    bytecode: Vec<u8>,
}

impl UupsAuthorizationBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<UupsAuthorizationBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(120) {
            if self.is_uups_upgrade_function(i) {
                if !self.has_authorization_check(i, i + 120) {
                    vulnerabilities.push(UupsAuthorizationBypassVulnerability::NoAuthorizationCheck {
                        description: "UUPS upgradeTo() without authorization check - anyone can upgrade".to_string(),
                        location: i,
                        confidence: 0.95,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_uups_upgrade_function(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        // upgradeTo: 0x3659cfe6, upgradeToAndCall: 0x4f1ef286
        let selectors = [[0x36, 0x59, 0xcf, 0xe6], [0x4f, 0x1e, 0xf2, 0x86]];
        selectors.iter().any(|sel| {
            self.bytecode[location..location + 20].windows(4).any(|w| w == sel)
        })
    }
    
    fn has_authorization_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Must check CALLER against authorized address
        let has_caller = self.bytecode[start..range_end].iter().any(|&b| b == 0x33);
        let has_comparison = self.bytecode[start..range_end].iter().any(|&b| b == 0x14);
        let has_revert = self.bytecode[start..range_end].iter().any(|&b| b == 0xFD);
        
        has_caller && has_comparison && has_revert
    }
}
