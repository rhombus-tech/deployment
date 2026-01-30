use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OptimismFaultProofVulnerability {
    DisputeGameManipulation,
    FaultProofWindowExploit,
    OutputRootDesync,
    BondSlashingBypass,
    ChallengeResolutionError,
    InvalidProofSubmission,
    TimelockBypass,
    WithdrawalProofForgery,
    L2ToL1MessageProof,
    StateCommitmentMismatch,
}

pub struct OptimismFaultProofDetector {
    bytecode: Vec<u8>,
}

impl OptimismFaultProofDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<OptimismFaultProofVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_dispute_validation() {
            vulnerabilities.push(OptimismFaultProofVulnerability::DisputeGameManipulation);
        }
        vulnerabilities
    }

    fn has_dispute_validation(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x54 && w[1] == 0x11)
    }
}
