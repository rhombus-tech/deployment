use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Erc4337AggregatorVulnerability {
    SignatureAggregationForging,
    BLSVerificationBypass,
    AggregatorStakingExploit,
    BatchValidationError,
    MaliciousAggregatorCollusion,
    NonceManipulation,
    UserOpReordering,
    AggregatedSignatureReplay,
    InvalidBundleSubmission,
    GasEstimationExploit,
}

pub struct Erc4337AggregatorDetector {
    bytecode: Vec<u8>,
}

impl Erc4337AggregatorDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc4337AggregatorVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_signature_validation() {
            vulnerabilities.push(Erc4337AggregatorVulnerability::SignatureAggregationForging);
        }
        vulnerabilities
    }

    fn has_signature_validation(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x20 && w[1] == 0x14)
    }
}
