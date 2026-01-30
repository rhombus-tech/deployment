use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LockedEtherVulnerability {
    AcceptsEthNoWithdraw { description: String, location: usize, confidence: f32 },
    PayableFallbackNoWithdraw { description: String, location: usize },
}

pub struct LockedEtherDetector {
    bytecode: Vec<u8>,
}

impl LockedEtherDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LockedEtherVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.accepts_eth() && !self.has_withdraw_function() {
            vulnerabilities.push(LockedEtherVulnerability::AcceptsEthNoWithdraw {
                description: "Contract accepts ETH but has no withdrawal function - funds locked forever".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        vulnerabilities
    }
    
    fn accepts_eth(&self) -> bool {
        // Fallback or receive function (CALLVALUE check)
        self.bytecode.iter().any(|&b| b == 0x34) // CALLVALUE
    }
    
    fn has_withdraw_function(&self) -> bool {
        // CALL opcode (to send ETH out)
        self.bytecode.iter().any(|&b| b == 0xF1)
    }
}
