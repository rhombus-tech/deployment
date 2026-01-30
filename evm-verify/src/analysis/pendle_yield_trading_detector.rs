use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PendleYieldVulnerability {
    YieldTokenManipulation,
    AMMLiquidityExploit,
    ImpliedAPYManipulation,
    FlashLoanYieldArbitrage,
    OracleYieldMismatch,
    MaturityExploitWindow,
    PTYTPricingError,
    SwapFeeManipulation,
    LiquidityProvisionRisk,
    YieldAccrualBypass,
}

pub struct PendleYieldTradingDetector {
    bytecode: Vec<u8>,
}

impl PendleYieldTradingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PendleYieldVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_oracle_validation() {
            vulnerabilities.push(PendleYieldVulnerability::OracleYieldMismatch);
        }
        if !self.has_maturity_check() {
            vulnerabilities.push(PendleYieldVulnerability::MaturityExploitWindow);
        }
        vulnerabilities
    }

    fn has_oracle_validation(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x50 && w[1] == 0x14)
    }

    fn has_maturity_check(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x42 && w[1] == 0x11)
    }
}
