use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LayerzeroRelayerCentralizationVulnerability {
    SingleRelayerDependency { description: String, location: usize, confidence: f32 },
    RelayerCensorship { description: String, location: usize, confidence: f32 },
    UncheckedRelayerSignature { description: String, location: usize, confidence: f32 },
}

pub struct LayerzeroRelayerCentralizationDetector {
    bytecode: Vec<u8>,
}

impl LayerzeroRelayerCentralizationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LayerzeroRelayerCentralizationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.uses_relayer() && !self.has_multiple_relayers() {
            vulnerabilities.push(LayerzeroRelayerCentralizationVulnerability::SingleRelayerDependency {
                description: "Single relayer dependency - centralization risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.validates_relayer() && !self.has_fallback() {
            vulnerabilities.push(LayerzeroRelayerCentralizationVulnerability::RelayerCensorship {
                description: "Relayer validation without fallback - censorship risk".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.checks_signature() && !self.validates_threshold() {
            vulnerabilities.push(LayerzeroRelayerCentralizationVulnerability::UncheckedRelayerSignature {
                description: "Signature check without threshold - single signer risk".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn uses_relayer(&self) -> bool {
        let caller_count = self.bytecode.iter().filter(|&&b| b == 0x33).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        caller_count > 0 && eq_count > 2
    }
    
    fn has_multiple_relayers(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let or_count = self.bytecode.iter().filter(|&&b| b == 0x17).count();
        sload_count > 4 && or_count > 1
    }
    
    fn validates_relayer(&self) -> bool {
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        eq_count > 3 && jumpi_count > 2
    }
    
    fn has_fallback(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        sload_count > 5 && iszero_count > 2
    }
    
    fn checks_signature(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        staticcall_count > 1
    }
    
    fn validates_threshold(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        sload_count > 3 && gt_count > 1
    }
}
