/// Mode Network Sequencer Fee Sharing (SFS) Detector
/// Mode L2 contract revenue sharing

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeSfsVulnerability {
    pub vulnerability_type: ModeSfsVulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModeSfsVulnerabilityType {
    SfsRegistrationBypass,          // Register contract without ownership
    FeeRecipientManipulation,       // Change fee recipient unauthorized
    UnclaimedFeesExposure,          // Fees not claimed, exploitable
    SfsTokenIdSpoofing,             // Spoof SFS NFT ownership
}

pub struct ModeNetworkSfsDetector {
    bytecode: Vec<u8>,
}

impl ModeNetworkSfsDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<ModeSfsVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: SFS registration without access control
        for i in 0..self.bytecode.len().saturating_sub(15) {
            let mut registers_sfs = false;
            let mut checks_owner = false;
            
            for j in i..self.bytecode.len().min(i + 15) {
                if self.bytecode[j] == 0xF1 { registers_sfs = true; }
                if self.bytecode[j] == 0x33 && j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x14 {
                    checks_owner = true;
                }
            }
            
            if registers_sfs && !checks_owner {
                vulnerabilities.push(ModeSfsVulnerability {
                    vulnerability_type: ModeSfsVulnerabilityType::FeeRecipientManipulation,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "SFS fee recipient can be changed without authorization.".to_string(),
                    exploit_scenario: "1. Popular DEX on Mode generates $1M/month sequencer fees\n\
                                      2. Fees registered to project treasury\n\
                                      3. assignSFS() function has no access control\n\
                                      4. Attacker calls assignSFS(attackerTokenId)\n\
                                      5. Future sequencer fees redirect to attacker\n\
                                      6. Project loses $1M/month revenue stream\n\
                                      7. $12M annual loss from fee redirection".to_string(),
                    recommendation: "Add onlyOwner to assignSFS(). Make SFS assignment immutable after first set. \
                                  Validate tokenId ownership.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}
