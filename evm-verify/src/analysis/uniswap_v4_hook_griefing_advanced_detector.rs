use serde::{Serialize, Deserialize};

/// Uniswap V4 Hook Griefing Advanced Detection
/// 
/// V4 hooks can grief swap operations through:
/// 1. Excessive gas consumption
/// 2. Always reverting
/// 3. Manipulating return values
/// 4. Reentrancy attacks via hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UniswapV4HookGriefingAdvancedVulnerability {
    /// Critical: Hook can grief all swaps
    HookDoSRisk {
        description: String,
        location: usize,
    },
    /// High: Hook has no gas limit
    UnlimitedHookGas {
        description: String,
        location: usize,
    },
    /// High: Hook return value not validated
    UnvalidatedHookReturn {
        description: String,
        location: usize,
    },
    /// Medium: Hook can reenter pool
    HookReentrancyRisk {
        description: String,
        location: usize,
    },
}

pub struct UniswapV4HookGriefingAdvancedDetector {
    bytecode: Vec<u8>,
}

impl UniswapV4HookGriefingAdvancedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<UniswapV4HookGriefingAdvancedVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Hook calls without gas limits
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.is_hook_call(i) {
                let has_gas_limit = self.has_gas_limit_before_call(i);
                
                if !has_gas_limit {
                    vulnerabilities.push(UniswapV4HookGriefingAdvancedVulnerability::UnlimitedHookGas {
                        description: "Hook call without gas limit - can DoS pool".to_string(),
                        location: i,
                    });
                }
                
                // Check return value validation
                let validates_return = self.validates_hook_return(i);
                
                if !validates_return {
                    vulnerabilities.push(UniswapV4HookGriefingAdvancedVulnerability::UnvalidatedHookReturn {
                        description: "Hook return value not validated".to_string(),
                        location: i,
                    });
                }
                
                // Check reentrancy protection
                let has_reentrancy_guard = self.has_hook_reentrancy_guard(i);
                
                if !has_reentrancy_guard {
                    vulnerabilities.push(UniswapV4HookGriefingAdvancedVulnerability::HookReentrancyRisk {
                        description: "Hook can reenter pool functions".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_hook_call(&self, location: usize) -> bool {
        // Hook calls are external calls to hook address
        self.bytecode[location] == 0xf1 || self.bytecode[location] == 0xfa
    }
    
    fn has_gas_limit_before_call(&self, location: usize) -> bool {
        let start = location.saturating_sub(20);
        self.bytecode[start..location].iter().any(|&b| b == 0x5a) // GAS opcode
    }
    
    fn validates_hook_return(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 20, self.bytecode.len());
        self.bytecode[location..end]
            .windows(2)
            .any(|w| w[0] == 0x15 || w[0] == 0x14) // ISZERO or EQ
    }
    
    fn has_hook_reentrancy_guard(&self, location: usize) -> bool {
        let start = location.saturating_sub(30);
        self.bytecode[start..location]
            .windows(3)
            .any(|w| w[0] == 0x54 && w[1] == 0x15 && w[2] == 0x57) // SLOAD, ISZERO, JUMPI
    }
}
