use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransitSwapVulnerability {
    UserControlledCalldata { description: String, location: usize, confidence: f32 },
    MissingTargetWhitelist { description: String, location: usize, confidence: f32 },
    NoReentrancyProtection { description: String, location: usize, confidence: f32 },
    ArbitraryDelegatecall { description: String, location: usize, confidence: f32 },
}

pub struct TransitSwapArbitraryCallDetector {
    bytecode: Vec<u8>,
}

impl TransitSwapArbitraryCallDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<TransitSwapVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_user_controlled_calldata());
        vulnerabilities.extend(self.detect_missing_whitelist());
        vulnerabilities.extend(self.detect_arbitrary_delegatecall());
        vulnerabilities
    }
    
    fn detect_user_controlled_calldata(&self) -> Vec<TransitSwapVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if i + 80 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 80];
                let has_call = section.contains(&0xF1) || section.contains(&0xFA);
                let has_calldataload = section.contains(&0x35);
                let has_validation = section.windows(10).any(|w| {
                    w.contains(&0x14) && w.contains(&0x15) && w.contains(&0xFD)
                });
                if has_call && has_calldataload && !has_validation {
                    vulnerabilities.push(TransitSwapVulnerability::UserControlledCalldata {
                        description: format!("External call at PC {} uses user-provided calldata without validation. Transit Swap exploit: attacker passed malicious calldata → called transferFrom on user tokens → drained $29M. Must validate call targets and selectors.", i),
                        location: i,
                        confidence: 0.93,
                    });
                }
            }
        }
        vulnerabilities
    }
    
    fn detect_missing_whitelist(&self) -> Vec<TransitSwapVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if i + 100 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 100];
                let has_external_call = section.contains(&0xF1);
                let loads_target_from_calldata = section.contains(&0x35);
                let checks_whitelist = section.windows(15).any(|w| {
                    w.contains(&0x54) && w.contains(&0x14) && w.contains(&0xFD)
                });
                if has_external_call && loads_target_from_calldata && !checks_whitelist {
                    vulnerabilities.push(TransitSwapVulnerability::MissingTargetWhitelist {
                        description: format!("Arbitrary external call target at PC {}. Should maintain whitelist of allowed contract addresses. Reject calls to EOAs or unknown contracts.", i),
                        location: i,
                        confidence: 0.90,
                    });
                }
            }
        }
        vulnerabilities
    }
    
    fn detect_arbitrary_delegatecall(&self) -> Vec<TransitSwapVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if i + 60 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 60];
                let has_delegatecall = section.contains(&0xF4);
                let user_controlled = section.contains(&0x35);
                if has_delegatecall && user_controlled {
                    vulnerabilities.push(TransitSwapVulnerability::ArbitraryDelegatecall {
                        description: format!("DELEGATECALL with user-controlled target at PC {}. CRITICAL: delegatecall executes in caller's context → can modify storage, steal funds. Never allow user-controlled delegatecall targets.", i),
                        location: i,
                        confidence: 0.97,
                    });
                }
            }
        }
        vulnerabilities
    }
}
