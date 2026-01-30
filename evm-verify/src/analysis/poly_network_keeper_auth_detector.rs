use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolyNetworkVulnerability {
    MissingKeeperAuth { description: String, location: usize, confidence: f32 },
    CrossChainReplay { description: String, location: usize, confidence: f32 },
    WeakRelayerValidation { description: String, location: usize, confidence: f32 },
    BypassableKeeperCheck { description: String, location: usize, confidence: f32 },
}

pub struct PolyNetworkKeeperAuthDetector {
    bytecode: Vec<u8>,
}

impl PolyNetworkKeeperAuthDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<PolyNetworkVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_missing_keeper_auth());
        vulnerabilities.extend(self.detect_cross_chain_replay());
        vulnerabilities.extend(self.detect_weak_relayer_validation());
        vulnerabilities
    }
    
    fn detect_missing_keeper_auth(&self) -> Vec<PolyNetworkVulnerability> {
        let mut vulnerabilities = Vec::new();
        let execute_sigs = [&[0xfe, 0x9d, 0x93, 0x03][..], &[0xb6, 0x1d, 0x27, 0xf6][..]];
        for sig in &execute_sigs {
            for i in 0..self.bytecode.len().saturating_sub(4) {
                if &self.bytecode[i..i + 4] == *sig {
                    let section = &self.bytecode[i..std::cmp::min(i + 150, self.bytecode.len())];
                    let has_caller_check = section.contains(&0x33) && section.contains(&0x14);
                    let has_keeper_validation = section.windows(10).any(|w| w.contains(&0x54) && w.contains(&0x14) && w.contains(&0xFD));
                    if !has_caller_check || !has_keeper_validation {
                        vulnerabilities.push(PolyNetworkVulnerability::MissingKeeperAuth {
                            description: format!("Cross-chain execution at PC {} lacks keeper/relayer authorization. Poly Network exploit: anyone could call executeTransaction(). Must validate msg.sender is authorized keeper.", i),
                            location: i,
                            confidence: 0.93,
                        });
                    }
                }
            }
        }
        vulnerabilities
    }
    
    fn detect_cross_chain_replay(&self) -> Vec<PolyNetworkVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if i + 100 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 100];
                let has_cross_chain = section.contains(&0x46) || section.contains(&0x35);
                let has_nonce_tracking = section.windows(5).any(|w| w.contains(&0x54) && w.contains(&0x55));
                if has_cross_chain && !has_nonce_tracking {
                    vulnerabilities.push(PolyNetworkVulnerability::CrossChainReplay {
                        description: format!("Cross-chain message at PC {} lacks nonce/replay protection. Messages from other chains could be replayed. Add per-chain nonce tracking.", i),
                        location: i,
                        confidence: 0.89,
                    });
                }
            }
        }
        vulnerabilities
    }
    
    fn detect_weak_relayer_validation(&self) -> Vec<PolyNetworkVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(120) {
            if i + 120 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 120];
                let has_signature_verify = section.contains(&0xFA) && section.windows(4).any(|w| w == &[0x00, 0x00, 0x00, 0x01]);
                let has_signer_whitelist = section.windows(8).any(|w| w.contains(&0x54) && w.contains(&0x14));
                if has_signature_verify && !has_signer_whitelist {
                    vulnerabilities.push(PolyNetworkVulnerability::WeakRelayerValidation {
                        description: format!("Relayer signature at PC {} not checked against authorized list. Anyone with valid ECDSA sig could act as relayer. Maintain whitelist of authorized relayers.", i),
                        location: i,
                        confidence: 0.87,
                    });
                }
            }
        }
        vulnerabilities
    }
}
