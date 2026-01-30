use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Erc4337PaymasterVulnerability {
    PaymasterStakingBypass,
    PostOpReentrancy,
    ValidationDataForgery,
    GasSponsorshipAbuse,
    PaymasterDepositDrain,
    ContextManipulation,
    UnlimitedPayment,
    PaymasterChaining,
    SignatureReplayAttack,
    EntryPointBypass,
}

pub struct Erc4337PaymasterDetector {
    bytecode: Vec<u8>,
}

impl Erc4337PaymasterDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc4337PaymasterVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_stake_check() {
            vulnerabilities.push(Erc4337PaymasterVulnerability::PaymasterStakingBypass);
        }
        vulnerabilities
    }

    fn has_stake_check(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x54 && w[1] == 0x31)
    }
}
