use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ArbitrumBoldVulnerability {
    AssertionTreeManipulation,
    EdgeBisectionExploit,
    OneStepProofForgery,
    StakeManipulation,
    ChallengeManagerBypass,
    ExecutionProofInvalid,
    DelayAttackVector,
    ValidatorCollusion,
    BondRecoveryBypass,
    RollupStateDesync,
}

pub struct ArbitrumBoldDetector {
    bytecode: Vec<u8>,
}

impl ArbitrumBoldDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ArbitrumBoldVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_assertion_check() {
            vulnerabilities.push(ArbitrumBoldVulnerability::AssertionTreeManipulation);
        }
        vulnerabilities
    }

    fn has_assertion_check(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x54 && w[1] == 0x15)
    }
}
