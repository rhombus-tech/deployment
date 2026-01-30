use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KernelAccountVulnerability {
    ValidatorPluginBypass,
    ExecutorPermissionEscalation,
    KernelUpgradeExploit,
    SelectorValidation,
    PluginMetadataForging,
    KernelStorageCollision,
    ValidatorChainManipulation,
    ExecutorBatching,
    PluginEnableDisable,
    RootAccessExploit,
}

pub struct KernelAccountDetector {
    bytecode: Vec<u8>,
}

impl KernelAccountDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<KernelAccountVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_validator_check() {
            vulnerabilities.push(KernelAccountVulnerability::ValidatorPluginBypass);
        }
        vulnerabilities
    }

    fn has_validator_check(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x54 && w[1] == 0x37)
    }
}
