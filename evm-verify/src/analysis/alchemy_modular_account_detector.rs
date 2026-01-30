use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlchemyModularAccountVulnerability {
    PluginInstallationBypass,
    PluginManifestForgery,
    HookExecutionOrder,
    ValidationPluginChain,
    PluginStorageCollision,
    PluginDependencyExploit,
    PluginUninstallRisk,
    CrossPluginReentrancy,
    PluginPermissionEscalation,
    ModularAccountUpgrade,
}

pub struct AlchemyModularAccountDetector {
    bytecode: Vec<u8>,
}

impl AlchemyModularAccountDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AlchemyModularAccountVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_plugin_validation() {
            vulnerabilities.push(AlchemyModularAccountVulnerability::PluginInstallationBypass);
        }
        vulnerabilities
    }

    fn has_plugin_validation(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x54 && w[1] == 0x35)
    }
}
