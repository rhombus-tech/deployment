use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ExactlyProtocolVulnerability {
    FixedBorrowRateManipulation,
    FloatingRateBypass,
    MaturityPoolExploit,
    InterestRateModelFlaw,
    UtilizationRateGaming,
    EarlyRepaymentPenaltyBypass,
    CollateralSeizureError,
    LiquidityPoolImbalance,
    RewardDistributionManipulation,
    CrossMaturityArbitrage,
}

pub struct ExactlyProtocolDetector {
    bytecode: Vec<u8>,
}

impl ExactlyProtocolDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ExactlyProtocolVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_rate_validation() {
            vulnerabilities.push(ExactlyProtocolVulnerability::InterestRateModelFlaw);
        }
        vulnerabilities
    }

    fn has_rate_validation(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x04 && w[1] == 0x11)
    }
}
