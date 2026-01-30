use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StarknetBridgeVulnerability {
    L1ToL2MessageCancellation,
    StarknetCoreContractExploit,
    CairoVMStateDesync,
    L1HandlerFunctionBypass,
    WithdrawalMessageForging,
    StarknetEthBridgeManipulation,
    FactRegistryBypass,
    SequencerStateUpdate,
    ProofVerificationGap,
    CrossLayerReentrancy,
}

pub struct StarknetBridgeDetector {
    bytecode: Vec<u8>,
}

impl StarknetBridgeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<StarknetBridgeVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_l1_handler_validation() {
            vulnerabilities.push(StarknetBridgeVulnerability::L1HandlerFunctionBypass);
        }
        vulnerabilities
    }

    fn has_l1_handler_validation(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x54 && w[1] == 0x21)
    }
}
