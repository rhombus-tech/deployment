use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MetisBridgeVulnerability {
    SequencerDecentralization,
    MetisTokenBridgeExploit,
    L2ToL1StateCommitment,
    MEVManagementBypass,
    ValidatorPoolManipulation,
    OptimismForkDivergence,
    IPFSDataAvailabilityRisk,
    CrossChainMessageRelay,
    DepositLockManipulation,
    WithdrawalFinalization,
}

pub struct MetisBridgeDetector {
    bytecode: Vec<u8>,
}

impl MetisBridgeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MetisBridgeVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_sequencer_check() {
            vulnerabilities.push(MetisBridgeVulnerability::SequencerDecentralization);
        }
        vulnerabilities
    }

    fn has_sequencer_check(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x33 && w[1] == 0x19)
    }
}
