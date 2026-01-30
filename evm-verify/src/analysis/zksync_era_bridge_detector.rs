use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ZksyncEraBridgeVulnerability {
    L1ToL2TransactionForging,
    PriorityQueueManipulation,
    DiamondProxyExploit,
    ValidatorSetBypass,
    BootloaderManipulation,
    WithdrawalFinalizationError,
    FacetUpgradeVulnerability,
    MailboxSecurityGap,
    ProofVerificationBypass,
    L2ToL1LogForging,
}

pub struct ZksyncEraBridgeDetector {
    bytecode: Vec<u8>,
}

impl ZksyncEraBridgeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ZksyncEraBridgeVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_priority_check() {
            vulnerabilities.push(ZksyncEraBridgeVulnerability::PriorityQueueManipulation);
        }
        vulnerabilities
    }

    fn has_priority_check(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x54 && w[1] == 0x16)
    }
}
