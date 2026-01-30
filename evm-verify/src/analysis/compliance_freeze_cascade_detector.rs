use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceFreezeCascadeVulnerability {
    DomainWideFreezeRisk { description: String, location: usize, confidence: f32 },
    ThirdPartyFreezePropagation { description: String, location: usize, confidence: f32 },
    NoFreezeIsolation { description: String, location: usize, confidence: f32 },
}

pub struct ComplianceFreezeCascadeDetector {
    bytecode: Vec<u8>,
}

impl ComplianceFreezeCascadeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ComplianceFreezeCascadeVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_domain_wide_compliance() && !self.isolates_freeze_scope() {
            vulnerabilities.push(ComplianceFreezeCascadeVulnerability::DomainWideFreezeRisk {
                description: "Domain-wide compliance without scope isolation - cascade freeze risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.checks_third_party_compliance() && !self.validates_freeze_source() {
            vulnerabilities.push(ComplianceFreezeCascadeVulnerability::ThirdPartyFreezePropagation {
                description: "Third-party compliance checks without validation - freeze propagation".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.implements_token_freeze() && self.has_composed_interactions() {
            vulnerabilities.push(ComplianceFreezeCascadeVulnerability::NoFreezeIsolation {
                description: "Token freeze in composed system - lack of isolation causes cascade".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn has_domain_wide_compliance(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        staticcall_count > 2 && sload_count > 5
    }
    
    fn isolates_freeze_scope(&self) -> bool {
        // Function-specific or address-specific checks
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let and_count = self.bytecode.iter().filter(|&&b| b == 0x16).count();
        eq_count > 3 && and_count > 1
    }
    
    fn checks_third_party_compliance(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        staticcall_count > 3 && iszero_count > 2
    }
    
    fn validates_freeze_source(&self) -> bool {
        // Whitelist of compliance providers
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        sload_count > 4 && eq_count > 4
    }
    
    fn implements_token_freeze(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        let revert_count = self.bytecode.iter().filter(|&&b| b == 0xFD).count();
        sload_count > 3 && iszero_count > 1 && revert_count > 0
    }
    
    fn has_composed_interactions(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xF4).count();
        call_count > 3
    }
}
