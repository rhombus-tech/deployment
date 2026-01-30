use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RadiantV2Vulnerability {
    DynamicLTVManipulation,
    LockingMechanismBypass,
    EligibilityRequirementBypass,
    EmissionControllerExploit,
    VestingScheduleManipulation,
    MultiFeeDistributorGaming,
    PriceProviderDesync,
    LeverageLoopingExploit,
    IncentiveControllerBypass,
    BorrowingPowerManipulation,
}

pub struct RadiantV2AdvancedDetector {
    bytecode: Vec<u8>,
}

impl RadiantV2AdvancedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<RadiantV2Vulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_ltv_validation() {
            vulnerabilities.push(RadiantV2Vulnerability::DynamicLTVManipulation);
        }
        vulnerabilities
    }

    fn has_ltv_validation(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x04 && w[1] == 0x11)
    }
}
