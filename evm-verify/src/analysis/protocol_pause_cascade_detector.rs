use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProtocolPauseCascadeVulnerability {
    UnprotectedPauseDependency { description: String, location: usize, confidence: f32 },
    MissingCircuitBreaker { description: String, location: usize, confidence: f32 },
    CascadeRisk { description: String, location: usize, confidence: f32 },
}

pub struct ProtocolPauseCascadeDetector {
    bytecode: Vec<u8>,
}

impl ProtocolPauseCascadeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ProtocolPauseCascadeVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_external_pause_dependency() && !self.has_pause_isolation() {
            vulnerabilities.push(ProtocolPauseCascadeVulnerability::UnprotectedPauseDependency {
                description: "Protocol depends on external pause state without isolation - cascade risk".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.has_pause_mechanism() && !self.has_circuit_breaker() {
            vulnerabilities.push(ProtocolPauseCascadeVulnerability::MissingCircuitBreaker {
                description: "Pause mechanism without circuit breaker - can freeze composed protocols".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        if self.has_multiple_protocol_calls() && self.has_pause_checks() {
            vulnerabilities.push(ProtocolPauseCascadeVulnerability::CascadeRisk {
                description: "Multiple protocol interactions with pause checks - cascade failure risk".to_string(),
                location: 0,
                confidence: 0.75,
            });
        }
        
        vulnerabilities
    }
    
    fn has_external_pause_dependency(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        staticcall_count > 2 && sload_count > 3
    }
    
    fn has_pause_isolation(&self) -> bool {
        let try_catch_pattern = self.bytecode.windows(3).any(|w| w == [0xFA, 0x3D, 0x57]);
        try_catch_pattern
    }
    
    fn has_pause_mechanism(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        sload_count > 2 && jumpi_count > 3
    }
    
    fn has_circuit_breaker(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        timestamp_count > 0 && gt_count > 2
    }
    
    fn has_multiple_protocol_calls(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xFA).count();
        call_count > 5
    }
    
    fn has_pause_checks(&self) -> bool {
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        iszero_count > 4
    }
}
