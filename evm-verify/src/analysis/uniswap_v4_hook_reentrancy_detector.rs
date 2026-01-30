use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniswapV4HookVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct UniswapV4HookReentrancyDetector {
    bytecode: Vec<u8>,
}

impl UniswapV4HookReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<UniswapV4HookVulnerability> {
        let mut vulnerabilities = Vec::new();

        // CRITICAL FIX: Only analyze if contract implements Uniswap V4 hooks
        if !self.is_uniswap_v4_hook() {
            return vulnerabilities; // Empty - not a Uniswap V4 hook contract
        }

        vulnerabilities.extend(self.detect_before_swap_hook_reentrancy());
        vulnerabilities.extend(self.detect_after_swap_state_manipulation());
        vulnerabilities.extend(self.detect_hook_permission_bypass());

        vulnerabilities
    }

    fn detect_before_swap_hook_reentrancy(&self) -> Vec<UniswapV4HookVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (beforeSwap hook)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_hook_selector = window.windows(4).any(|w| {
                    w[0] == 0x60 && w[1] == 0x00 // Placeholder for hook selector
                });
                
                if has_hook_selector {
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_state_update_after = forward.iter().any(|&b| b == 0x55); // SSTORE
                    let has_reentrancy_guard = window.iter().filter(|&&b| b == 0x55).count() >= 2;
                    
                    if has_state_update_after && !has_reentrancy_guard {
                        vulns.push(UniswapV4HookVulnerability {
                            pc,
                            vulnerability_type: "BeforeSwapHookReentrancy".to_string(),
                            description: format!(
                                "Uniswap V4 beforeSwap hook call at PC {} allows reentrancy. Attack: hook contract reenters pool during \
                                beforeSwap, manipulates state before swap executes. Example: beforeSwap reads pool reserves, hook reenters and \
                                swaps, original swap uses stale reserves. Missing: reentrancy lock before hook calls, state snapshot validation, \
                                hooks registry whitelist. Should set nonReentrant before calling untrusted hooks.",
                                pc
                            ),
                            confidence: 0.87,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_after_swap_state_manipulation(&self) -> Vec<UniswapV4HookVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (swap state update)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_after_hook = window.iter().any(|&b| b == 0xF1); // CALL
                
                if has_after_hook {
                    let has_return_validation = window.iter().any(|&b| b == 0x15); // ISZERO
                    let has_state_lock = window.iter().filter(|&&b| b == 0x55).count() >= 3;
                    
                    if !has_return_validation {
                        vulns.push(UniswapV4HookVulnerability {
                            pc,
                            vulnerability_type: "AfterSwapStateManipulation".to_string(),
                            description: format!(
                                "State update at PC {} followed by afterSwap hook without validation. Attack: afterSwap hook returns manipulated \
                                data, influences accounting/fees. Pool updates reserves, calls afterSwap, hook returns false data about fees/amounts, \
                                pool records incorrect state. Missing: hook return value validation, state finalization before hooks, immutable swap \
                                result. Should finalize all state before calling afterSwap hooks.",
                                pc
                            ),
                            confidence: 0.85,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_hook_permission_bypass(&self) -> Vec<UniswapV4HookVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (hook call)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_hook_address = window.iter().any(|&b| b == 0x54); // SLOAD (hook address)
                
                if has_hook_address {
                    let has_permission_check = window.iter().any(|&b| b == 0x14); // EQ (address comparison)
                    let has_flags_validation = window.iter().filter(|&&b| matches!(b, 0x16 | 0x17)).count() >= 2; // AND, OR
                    
                    if !has_permission_check || !has_flags_validation {
                        vulns.push(UniswapV4HookVulnerability {
                            pc,
                            vulnerability_type: "HookPermissionBypass".to_string(),
                            description: format!(
                                "Hook call at PC {} without permission flags validation. Uniswap V4 hooks have permission bits (beforeSwap, afterSwap, \
                                etc.). Attack: pool configured with malicious hook, hook doesn't have beforeModifyPosition permission but gets called \
                                anyway, executes unauthorized logic. Missing: hook flags bitwise validation, permission mask enforcement, hook capability \
                                check. Should validate: hookAddress.getHookPermissions() & REQUIRED_PERMISSION != 0.",
                                pc
                            ),
                            confidence: 0.83,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    /// Check if contract implements Uniswap V4 hook interface
    /// Verifies presence of hook function selectors
    fn is_uniswap_v4_hook(&self) -> bool {
        let bytecode = &self.bytecode;
        
        // Uniswap V4 hook function selectors (first 4 bytes of keccak256)
        let hook_selectors = [
            [0x6d, 0x9f, 0x6d, 0x7d], // beforeInitialize(address,PoolKey,uint160,bytes)
            [0x5c, 0x6f, 0x0b, 0x9e], // afterInitialize(address,PoolKey,uint160,int24,bytes)
            [0x4a, 0x4f, 0xbe, 0xec], // beforeModifyPosition(address,PoolKey,ModifyPositionParams,bytes)
            [0x8c, 0x5b, 0x83, 0x85], // afterModifyPosition(address,PoolKey,ModifyPositionParams,BalanceDelta,bytes)
            [0x5c, 0x0d, 0x5e, 0x53], // beforeSwap(address,PoolKey,SwapParams,bytes)
            [0xf5, 0xe7, 0xb2, 0x10], // afterSwap(address,PoolKey,SwapParams,BalanceDelta,bytes)
            [0x47, 0xa7, 0xd1, 0x07], // beforeDonate(address,PoolKey,uint256,uint256,bytes)
            [0xc8, 0xe7, 0xa3, 0x3f], // afterDonate(address,PoolKey,uint256,uint256,bytes)
        ];
        
        // Check if bytecode contains any hook function selectors
        // A valid hook must implement at least one of these functions
        let mut found_hooks = 0;
        for selector in &hook_selectors {
            if self.contains_selector(selector) {
                found_hooks += 1;
            }
        }
        
        // Require at least 2 hook functions to be confident it's a real hook
        // (reduces false positives from random byte matches)
        found_hooks >= 2
    }
    
    /// Check if bytecode contains a specific function selector
    fn contains_selector(&self, selector: &[u8; 4]) -> bool {
        let bytecode = &self.bytecode;
        if bytecode.len() < 4 {
            return false;
        }
        
        // Look for the selector in the bytecode
        // Function selectors typically appear early in contract (function dispatcher)
        bytecode.windows(4)
            .take(500) // Only check first 500 bytes for efficiency
            .any(|window| window == selector)
    }
}
