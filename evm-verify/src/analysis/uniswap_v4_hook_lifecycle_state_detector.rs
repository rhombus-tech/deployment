use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UniswapV4HookLifecycleVulnerability {
    StateChangesBetweenHooks { description: String, location: usize, confidence: f32 },
    HookReentrancyRisk { description: String, location: usize, confidence: f32 },
}

pub struct UniswapV4HookLifecycleStateDetector {
    bytecode: Vec<u8>,
}

impl UniswapV4HookLifecycleStateDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<UniswapV4HookLifecycleVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Uniswap V4 hooks: beforeSwap, afterSwap, beforeAddLiquidity, afterAddLiquidity
        // Pattern: State changes between beforeX and afterX hooks
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            let section = &self.bytecode[i..std::cmp::min(i + 100, self.bytecode.len())];
            
            // Look for SSTORE (state modification)
            let has_state_modification = section.contains(&0x55); // SSTORE
            
            // Check if within hook callback pattern (external call returning to modify state)
            let has_external_call = section.contains(&0xF1) || section.contains(&0xFA);
            
            if has_state_modification && has_external_call {
                vulnerabilities.push(UniswapV4HookLifecycleVulnerability::StateChangesBetweenHooks {
                    description: format!("Hook at PC {} modifies state after external call. Uniswap V4: beforeSwap() called → swap executes → afterSwap() called. If state changes between hooks, assumptions break. Example: beforeSwap locks, swap happens, malicious afterSwap reenters. Ensure atomic hook execution or use reentrancy guards.", i),
                    location: i,
                    confidence: 0.87,
                });
            }
        }
        
        vulnerabilities
    }
}
