use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum GearboxCreditVulnerability {
    CreditAccountImpersonation,
    LeverageBypassExploit,
    AdapterWhitelistBypass,
    CreditFacadeManipulation,
    CollateralCheckBypass,
    HealthFactorManipulation,
    LiquidationThresholdExploit,
    AllowedTokensBypass,
    CreditManagerAccessControl,
    LeverageMultiplierExploit,
}

pub struct GearboxCreditAccountDetector {
    bytecode: Vec<u8>,
}

impl GearboxCreditAccountDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<GearboxCreditVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_access_control() {
            vulnerabilities.push(GearboxCreditVulnerability::CreditManagerAccessControl);
        }
        if !self.has_leverage_check() {
            vulnerabilities.push(GearboxCreditVulnerability::LeverageMultiplierExploit);
        }
        vulnerabilities
    }

    fn has_access_control(&self) -> bool {
        self.bytecode.windows(2).any(|w| w[0] == 0x54 && w[1] == 0x33)
    }

    fn has_leverage_check(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x04 && w[1] == 0x11)
    }
}
