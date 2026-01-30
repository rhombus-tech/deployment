use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LightAccountVulnerability {
    SimplifiedValidationBypass,
    OwnerTransferExploit,
    LightweightStorageRisk,
    MinimalProxyClone,
    InitializationReentrancy,
    OwnerSignatureReplay,
    EntryPointCompatibility,
    UpgradePathExploit,
    BatchCallValidation,
    GasOptimizationVulnerability,
}

pub struct LightAccountDetector {
    bytecode: Vec<u8>,
}

impl LightAccountDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LightAccountVulnerability> {
        let mut vulnerabilities = Vec::new();
        if !self.has_initialization_check() {
            vulnerabilities.push(LightAccountVulnerability::InitializationReentrancy);
        }
        vulnerabilities
    }

    fn has_initialization_check(&self) -> bool {
        self.bytecode.windows(3).any(|w| w[0] == 0x54 && w[1] == 0x41)
    }
}
