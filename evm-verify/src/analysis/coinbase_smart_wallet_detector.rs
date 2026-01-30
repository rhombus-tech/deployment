use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CoinbaseSmartWalletVulnerability {
    WebAuthnVerificationBypass { description: String, location: usize, confidence: f32 },
    PasskeyStorageExploit { description: String, location: usize, confidence: f32 },
    MultiOwnerManipulation { description: String, location: usize, confidence: f32 },
    CrossChainReplayRisk { description: String, location: usize, confidence: f32 },
    SignatureValidationError { description: String, location: usize, confidence: f32 },
    PasskeyRotation { description: String, location: usize, confidence: f32 },
    WebAuthnChallengeReuse { description: String, location: usize, confidence: f32 },
    OwnerAdditionRemoval { description: String, location: usize, confidence: f32 },
    ReplaySafeHashBypass { description: String, location: usize, confidence: f32 },
    BatchExecutionRisk { description: String, location: usize, confidence: f32 },
}

pub struct CoinbaseSmartWalletDetector {
    bytecode: Vec<u8>,
}

impl CoinbaseSmartWalletDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CoinbaseSmartWalletVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for (i, window) in self.bytecode.windows(3).enumerate() {
            if window[0] == 0x20 && window[1] == 0x15 {
                vulnerabilities.push(CoinbaseSmartWalletVulnerability::WebAuthnVerificationBypass {
                    description: "Missing WebAuthn verification".to_string(),
                    location: i,
                    confidence: 0.75,
                });
            }
            if window[0] == 0x33 && window[1] == 0x56 {
                vulnerabilities.push(CoinbaseSmartWalletVulnerability::PasskeyStorageExploit {
                    description: "Passkey storage vulnerability".to_string(),
                    location: i,
                    confidence: 0.80,
                });
            }
        }
        
        vulnerabilities
    }

    fn has_webauthn_validation(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x20 && w[1] == 0x15)
    }
}
