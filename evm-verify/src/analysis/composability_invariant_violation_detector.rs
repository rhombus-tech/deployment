use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComposabilityInvariantViolationVulnerability {
    BrokenInvariantChain { description: String, location: usize, confidence: f32 },
    UncheckedComposedCall { description: String, location: usize, confidence: f32 },
    InvariantLeakage { description: String, location: usize, confidence: f32 },
}

pub struct ComposabilityInvariantViolationDetector {
    bytecode: Vec<u8>,
}

impl ComposabilityInvariantViolationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ComposabilityInvariantViolationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_composed_calls() && !self.validates_invariants() {
            vulnerabilities.push(ComposabilityInvariantViolationVulnerability::BrokenInvariantChain {
                description: "Composed protocol calls without invariant validation - chain break risk".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.has_external_state_dependency() && !self.checks_return_values() {
            vulnerabilities.push(ComposabilityInvariantViolationVulnerability::UncheckedComposedCall {
                description: "External state dependency without return value checks - invariant violation".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        if self.modifies_shared_state() && !self.has_state_protection() {
            vulnerabilities.push(ComposabilityInvariantViolationVulnerability::InvariantLeakage {
                description: "Shared state modification without protection - invariant leakage to composed protocols".to_string(),
                location: 0,
                confidence: 0.75,
            });
        }
        
        vulnerabilities
    }
    
    fn has_composed_calls(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xF4 || b == 0xFA).count();
        call_count > 3
    }
    
    fn validates_invariants(&self) -> bool {
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        (eq_count + lt_count + gt_count) > 10
    }
    
    fn has_external_state_dependency(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        sload_count > 5 && call_count > 2
    }
    
    fn checks_return_values(&self) -> bool {
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        iszero_count > 2 && jumpi_count > 3
    }
    
    fn modifies_shared_state(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        sstore_count > 3
    }
    
    fn has_state_protection(&self) -> bool {
        let reentrancy_guard = self.bytecode.windows(4).any(|w| w == [0x54, 0x15, 0x57, 0x00]);
        reentrancy_guard
    }
}
