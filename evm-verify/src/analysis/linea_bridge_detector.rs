use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LineaBridgeVulnerability {
    LineaBridgeMessageService,
    L2MessageServiceExploit,
    RateLimitBypass,
    PauseManagerExploit,
    MessageClaimReplay,
    RollingHashManipulation,
    PostmanContractBypass,
    L1ToL2AnchoringError,
    FinalizedL2BlockDesync,
    CrossChainClaimForgery,
}

pub struct LineaBridgeDetector {
    bytecode: Vec<u8>,
}

impl LineaBridgeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LineaBridgeVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_rate_limit_check() {
            vulnerabilities.push(LineaBridgeVulnerability::RateLimitBypass);
        }
        vulnerabilities
    }

    fn has_rate_limit_check(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x11 && w[1] == 0x15)
    }
}
