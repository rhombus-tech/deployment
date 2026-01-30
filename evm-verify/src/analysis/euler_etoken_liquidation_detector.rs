use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EulerETokenVulnerability {
    DonateAttackVector,
    LiquidationHealthFactorBypass,
    CollateralFactorManipulation,
    BorrowIsolationBypass,
    SelfLiquidationExploit,
    ETokenReservesManipulation,
    TierViolationExploit,
    SubAccountBypass,
    RiskAdjustedValueError,
    CompoundInterestPrecisionLoss,
}

pub struct EulerETokenLiquidationDetector {
    bytecode: Vec<u8>,
}

impl EulerETokenLiquidationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EulerETokenVulnerability> {
        let mut vulnerabilities = Vec::new();
        let donate_selector = [0xed, 0x18, 0x08, 0x93];
        if self.bytecode.windows(4).any(|w| w == donate_selector) {
            if !self.has_donation_protection() {
                vulnerabilities.push(EulerETokenVulnerability::DonateAttackVector);
            }
        }
        vulnerabilities
    }

    fn has_donation_protection(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x54 && w[1] == 0x15)
    }
}
