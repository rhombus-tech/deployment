use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UniswapV4HookGriefingVulnerability {
    UnboundedHookExecution { description: String, location: usize, confidence: f32 },
    HookReentrancyRisk { description: String, location: usize, confidence: f32 },
    MaliciousHookDOS { description: String, location: usize, confidence: f32 },
}

pub struct UniswapV4HookGriefingDetector {
    bytecode: Vec<u8>,
}

impl UniswapV4HookGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<UniswapV4HookGriefingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.executes_hooks() && !self.limits_gas() {
            vulnerabilities.push(UniswapV4HookGriefingVulnerability::UnboundedHookExecution {
                description: "Uniswap v4 hook without gas limits - DoS via expensive hooks".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.calls_external_hook() && !self.has_reentrancy_guard() {
            vulnerabilities.push(UniswapV4HookGriefingVulnerability::HookReentrancyRisk {
                description: "External hook call without reentrancy protection - state manipulation".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.allows_hook_registration() && !self.validates_hook() {
            vulnerabilities.push(UniswapV4HookGriefingVulnerability::MaliciousHookDOS {
                description: "Hook registration without validation - malicious hook DoS".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn executes_hooks(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xF4).count();
        call_count > 3
    }
    
    fn limits_gas(&self) -> bool {
        let gas_count = self.bytecode.iter().filter(|&&b| b == 0x5A).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        gas_count > 0 && gt_count > 1
    }
    
    fn calls_external_hook(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        call_count > 2 && sload_count > 3
    }
    
    fn has_reentrancy_guard(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        sload_count > 3 && iszero_count > 2 && sstore_count > 2
    }
    
    fn allows_hook_registration(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        sstore_count > 3
    }
    
    fn validates_hook(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        staticcall_count > 1 && eq_count > 3 && jumpi_count > 3
    }
}
