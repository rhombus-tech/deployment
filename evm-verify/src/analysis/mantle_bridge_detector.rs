use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MantleBridgeVulnerability {
    MantleTokenGateway,
    BVMEigenDataLayerBridge,
    TSSSignerManipulation,
    CrossChainDataExploit,
    L1ToL2DepositGasLimit,
    BitDAIntegrationRisk,
    WithdrawalProverBypass,
    OptimismBridgeFork,
    MessageRelayerExploit,
    FinalityWindowBypass,
}

pub struct MantleBridgeDetector {
    bytecode: Vec<u8>,
}

impl MantleBridgeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MantleBridgeVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_tss_validation() {
            vulnerabilities.push(MantleBridgeVulnerability::TSSSignerManipulation);
        }
        vulnerabilities
    }

    fn has_tss_validation(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x54 && w[1] == 0x19)
    }
}
