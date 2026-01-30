use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ColendProtocolVulnerability {
    IsolatedPoolExploit { description: String, location: usize, confidence: f32 },
    SupplyCapManipulation { description: String, location: usize, confidence: f32 },
    BorrowCapBypass { description: String, location: usize, confidence: f32 },
    InterestRateStrategyFlaw { description: String, location: usize, confidence: f32 },
    ReserveConfigurationError { description: String, location: usize, confidence: f32 },
    EModeCategoryBypass { description: String, location: usize, confidence: f32 },
    LiquidationBonusGaming { description: String, location: usize, confidence: f32 },
    DebtCeilingManipulation { description: String, location: usize, confidence: f32 },
    SiloedBorrowingBypass { description: String, location: usize, confidence: f32 },
    FlashloanPremiumBypass { description: String, location: usize, confidence: f32 },
}

pub struct ColendProtocolDetector {
    bytecode: Vec<u8>,
}

impl ColendProtocolDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ColendProtocolVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for (i, window) in self.bytecode.windows(3).enumerate() {
            if window[0] == 0x11 && window[1] == 0x15 {
                vulnerabilities.push(ColendProtocolVulnerability::SupplyCapManipulation {
                    description: "Missing supply cap validation".to_string(),
                    location: i,
                    confidence: 0.75,
                });
            }
            if window[0] == 0x22 && window[1] == 0x33 {
                vulnerabilities.push(ColendProtocolVulnerability::BorrowCapBypass {
                    description: "Borrow cap bypass detected".to_string(),
                    location: i,
                    confidence: 0.80,
                });
            }
        }
        
        vulnerabilities
    }

    fn has_cap_validation(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x11 && w[1] == 0x15)
    }
}
