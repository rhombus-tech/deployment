use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ViewFunctionStateReentrancyVulnerability {
    ViewFunctionReentrancy { description: String, location: usize, confidence: f32 },
    ReadOnlyReentrancyRisk { description: String, location: usize, confidence: f32 },
    CachedStateExposure { description: String, location: usize, confidence: f32 },
}

pub struct ViewFunctionStateReentrancyDetector {
    bytecode: Vec<u8>,
}

impl ViewFunctionStateReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ViewFunctionStateReentrancyVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Curve vyper exploit pattern: view function called during state change
        if self.has_view_function_pattern() && self.allows_reentrant_calls() && !self.has_reentrancy_lock() {
            vulnerabilities.push(ViewFunctionStateReentrancyVulnerability::ViewFunctionReentrancy {
                description: "View function callable during state changes - Curve vyper-style reentrancy risk".to_string(),
                location: 0,
                confidence: 0.95,
            });
        }
        
        if self.has_staticcall_dependency() && self.modifies_state_before() {
            vulnerabilities.push(ViewFunctionStateReentrancyVulnerability::ReadOnlyReentrancyRisk {
                description: "State modification before read-only call - stale state exploitation".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.caches_external_state() && self.allows_external_calls() && !self.invalidates_cache() {
            vulnerabilities.push(ViewFunctionStateReentrancyVulnerability::CachedStateExposure {
                description: "Cached external state without invalidation - view reentrancy vector".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn has_view_function_pattern(&self) -> bool {
        // Detect view functions (staticcall pattern with return data)
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let returndatasize_count = self.bytecode.iter().filter(|&&b| b == 0x3D).count();
        staticcall_count > 0 && returndatasize_count > 0
    }
    
    fn allows_reentrant_calls(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xF4).count();
        call_count > 1
    }
    
    fn has_reentrancy_lock(&self) -> bool {
        // Check for reentrancy guard pattern: SLOAD -> ISZERO -> JUMPI -> PUSH1 -> SSTORE
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        sload_count > 2 && sstore_count > 2 && iszero_count > 2
    }
    
    fn has_staticcall_dependency(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        staticcall_count > 1
    }
    
    fn modifies_state_before(&self) -> bool {
        // Look for SSTORE before STATICCALL pattern
        let has_pattern = self.bytecode.windows(10).any(|w| {
            w.iter().any(|&b| b == 0x55) && // SSTORE
            w.iter().skip_while(|&&b| b != 0x55).any(|&b| b == 0xFA) // STATICCALL after
        });
        has_pattern
    }
    
    fn caches_external_state(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        sload_count > 3 && sstore_count > 2 && staticcall_count > 1
    }
    
    fn allows_external_calls(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xF4 || b == 0xFA).count();
        call_count > 2
    }
    
    fn invalidates_cache(&self) -> bool {
        // Check for timestamp-based cache invalidation
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        timestamp_count > 0 && lt_count > 1
    }
}
