use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScrollBridgeVulnerability {
    FinalizationProofBypass,
    BatchHeaderManipulation,
    ScrollChainCommitmentForgery,
    GatewayRouterExploit,
    L1MessageQueueExploit,
    L2ToL1MessageProof,
    ZkTrieProofInvalid,
    ScrollMessengerReentrancy,
    BatchVerificationSkip,
    WithdrawalRootMismatch,
}

pub struct ScrollBridgeDetector {
    bytecode: Vec<u8>,
}

impl ScrollBridgeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ScrollBridgeVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_finalization_check() {
            vulnerabilities.push(ScrollBridgeVulnerability::FinalizationProofBypass);
        }
        vulnerabilities
    }

    fn has_finalization_check(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x42 && w[1] == 0x14)
    }
}
