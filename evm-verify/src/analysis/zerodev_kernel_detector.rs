use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ZerodevKernelVulnerability {
    ECDSAValidatorBypass,
    SessionKeyManagerExploit,
    KillSwitchManipulation,
    PolicyEnforcementBypass,
    MultiChainAccountSync,
    ValidatorStorageSlot,
    PluginRegistryCorruption,
    ExecutionPolicyChain,
    ValidatorWeightManipulation,
    KernelFactoryClone,
}

pub struct ZerodevKernelDetector {
    bytecode: Vec<u8>,
}

impl ZerodevKernelDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ZerodevKernelVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_policy_validation() {
            vulnerabilities.push(ZerodevKernelVulnerability::PolicyEnforcementBypass);
        }
        vulnerabilities
    }

    fn has_policy_validation(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x54 && w[1] == 0x43)
    }
}
