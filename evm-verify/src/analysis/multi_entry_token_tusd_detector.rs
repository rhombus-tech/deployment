use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MultiEntryTokenTusdVulnerability {
    MultipleEntryPoints { description: String, location: usize, confidence: f32 },
    UncheckedDelegateCall { description: String, location: usize, confidence: f32 },
    ProxyInconsistency { description: String, location: usize, confidence: f32 },
}

pub struct MultiEntryTokenTusdDetector {
    bytecode: Vec<u8>,
}

impl MultiEntryTokenTusdDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MultiEntryTokenTusdVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_multiple_implementations() && !self.validates_entry_points() {
            vulnerabilities.push(MultiEntryTokenTusdVulnerability::MultipleEntryPoints {
                description: "Multiple implementation entry points without validation - TUSD-style risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.uses_delegatecall() && !self.validates_target() {
            vulnerabilities.push(MultiEntryTokenTusdVulnerability::UncheckedDelegateCall {
                description: "Delegatecall to unvalidated target - multiple entry point exploit".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.has_proxy_pattern() && self.has_logic_duplication() {
            vulnerabilities.push(MultiEntryTokenTusdVulnerability::ProxyInconsistency {
                description: "Proxy with duplicated logic - state inconsistency risk".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn has_multiple_implementations(&self) -> bool {
        let delegatecall_count = self.bytecode.iter().filter(|&&b| b == 0xF4).count();
        let extcodesize_count = self.bytecode.iter().filter(|&&b| b == 0x3B).count();
        delegatecall_count > 1 && extcodesize_count > 2
    }
    
    fn validates_entry_points(&self) -> bool {
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        eq_count > 3 && iszero_count > 2
    }
    
    fn uses_delegatecall(&self) -> bool {
        self.bytecode.iter().any(|&b| b == 0xF4)
    }
    
    fn validates_target(&self) -> bool {
        let extcodesize_count = self.bytecode.iter().filter(|&&b| b == 0x3B).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        extcodesize_count > 0 && iszero_count > 1
    }
    
    fn has_proxy_pattern(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let delegatecall_count = self.bytecode.iter().filter(|&&b| b == 0xF4).count();
        sload_count > 2 && delegatecall_count > 0
    }
    
    fn has_logic_duplication(&self) -> bool {
        let jumpdest_count = self.bytecode.iter().filter(|&&b| b == 0x5B).count();
        jumpdest_count > 10
    }
}
