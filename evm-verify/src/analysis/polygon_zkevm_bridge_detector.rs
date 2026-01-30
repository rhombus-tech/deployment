use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolygonZkevmBridgeVulnerability {
    MerkleProofForgery,
    GlobalExitRootManipulation,
    BridgeSequencerExploit,
    L1ToL2MessageReplay,
    EmergencyModeBypass,
    AssetBridgeMismatch,
    ClaimWithdrawalReentrancy,
    VerifierCircuitBypass,
    BatchProofInvalid,
    ForcedBatchExploit,
}

pub struct PolygonZkevmBridgeDetector {
    bytecode: Vec<u8>,
}

impl PolygonZkevmBridgeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PolygonZkevmBridgeVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_merkle_validation() {
            vulnerabilities.push(PolygonZkevmBridgeVulnerability::MerkleProofForgery);
        }
        vulnerabilities
    }

    fn has_merkle_validation(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x20 && w[1] == 0x14)
    }
}
