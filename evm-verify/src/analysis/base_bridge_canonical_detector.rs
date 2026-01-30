use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BaseBridgeVulnerability {
    StandardBridgeExploit,
    OptimismBridgeInheritance,
    MessagePassingRelay,
    CrossDomainMessengerBypass,
    L1CrossDomainMessenger,
    L2ToL1WithdrawalReplay,
    DepositTransactionForging,
    GasLimitManipulation,
    FinalityPeriodBypass,
    BridgeUpgradeVulnerability,
}

pub struct BaseBridgeCanonicalDetector {
    bytecode: Vec<u8>,
}

impl BaseBridgeCanonicalDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BaseBridgeVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_messenger_check() {
            vulnerabilities.push(BaseBridgeVulnerability::CrossDomainMessengerBypass);
        }
        vulnerabilities
    }

    fn has_messenger_check(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x33 && w[1] == 0x14)
    }
}
