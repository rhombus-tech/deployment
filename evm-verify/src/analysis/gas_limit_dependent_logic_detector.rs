use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GasLimitDependentLogicVulnerability {
    GasLimitDependency { description: String, location: usize, confidence: f32 },
    UnboundedGasConsumption { description: String, location: usize, confidence: f32 },
    BlockGasLimitAssumption { description: String, location: usize, confidence: f32 },
}

pub struct GasLimitDependentLogicDetector {
    bytecode: Vec<u8>,
}

impl GasLimitDependentLogicDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<GasLimitDependentLogicVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.uses_gasleft_in_logic() && !self.has_gas_buffer() {
            vulnerabilities.push(GasLimitDependentLogicVulnerability::GasLimitDependency {
                description: "Business logic depends on gas remaining - execution variability risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.has_unbounded_loop() && self.consumes_dynamic_gas() {
            vulnerabilities.push(GasLimitDependentLogicVulnerability::UnboundedGasConsumption {
                description: "Unbounded loop with dynamic gas consumption - DoS risk".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.assumes_block_gas_limit() && !self.validates_gas_available() {
            vulnerabilities.push(GasLimitDependentLogicVulnerability::BlockGasLimitAssumption {
                description: "Assumes block gas limit without validation - cross-chain incompatibility".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn uses_gasleft_in_logic(&self) -> bool {
        // GAS opcode (0x5A) used in conditional logic
        let gas_count = self.bytecode.iter().filter(|&&b| b == 0x5A).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        gas_count > 0 && jumpi_count > 2
    }
    
    fn has_gas_buffer(&self) -> bool {
        // Check for gas buffer subtraction before comparison
        let gas_count = self.bytecode.iter().filter(|&&b| b == 0x5A).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        gas_count > 0 && sub_count > 1 && gt_count > 0
    }
    
    fn has_unbounded_loop(&self) -> bool {
        // Loop without clear exit condition
        let jumpdest_count = self.bytecode.iter().filter(|&&b| b == 0x5B).count();
        let jump_count = self.bytecode.iter().filter(|&&b| b == 0x56).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        jumpdest_count > 3 && jump_count > 3 && lt_count < 2
    }
    
    fn consumes_dynamic_gas(&self) -> bool {
        // External calls or storage operations in loop
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xFA || b == 0xF4).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        call_count > 2 || sstore_count > 3
    }
    
    fn assumes_block_gas_limit(&self) -> bool {
        // Large constant compared with GAS
        let gas_count = self.bytecode.iter().filter(|&&b| b == 0x5A).count();
        let push_count = self.bytecode.iter().filter(|&&b| b >= 0x60 && b <= 0x7F).count();
        gas_count > 0 && push_count > 5
    }
    
    fn validates_gas_available(&self) -> bool {
        let gas_count = self.bytecode.iter().filter(|&&b| b == 0x5A).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        let require_pattern = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        gas_count > 0 && gt_count > 0 && require_pattern > 2
    }
}
