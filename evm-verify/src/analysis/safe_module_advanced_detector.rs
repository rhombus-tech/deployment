use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SafeModuleVulnerability {
    ModuleAuthorizationBypass,
    GuardManipulation,
    FallbackHandlerExploit,
    DelegateCallModule,
    ModuleTransactionReplay,
    SignatureThresholdBypass,
    ModuleChaining,
    SafeNonceDesync,
    ModuleAccessControl,
    CompatibilityFallbackRisk,
}

pub struct SafeModuleAdvancedDetector {
    bytecode: Vec<u8>,
}

impl SafeModuleAdvancedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SafeModuleVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_module_authorization() {
            vulnerabilities.push(SafeModuleVulnerability::ModuleAuthorizationBypass);
        }
        vulnerabilities
    }

    fn has_module_authorization(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x54 && w[1] == 0x33)
    }
}
