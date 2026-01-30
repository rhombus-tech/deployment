use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SoulWalletVulnerability {
    SocialRecoveryBypass,
    GuardianCollusion,
    RecoveryThresholdManipulation,
    GuardianAddRemove,
    RecoveryWindowExploit,
    TimelockBypassRecovery,
    GuardianSignatureForging,
    OwnershipTransferRisk,
    RecoveryReentrancy,
    GuardianStorageCorruption,
}

pub struct SoulWalletDetector {
    bytecode: Vec<u8>,
}

impl SoulWalletDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SoulWalletVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_guardian_validation() {
            vulnerabilities.push(SoulWalletVulnerability::SocialRecoveryBypass);
        }
        vulnerabilities
    }

    fn has_guardian_validation(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x54 && w[1] == 0x39)
    }
}
