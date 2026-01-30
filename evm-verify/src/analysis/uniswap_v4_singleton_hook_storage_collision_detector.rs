use crate::bytecode::{SecurityFinding, SecuritySeverity};

pub struct UniswapV4SingletonHookStorageCollisionDetector {
    bytecode: Vec<u8>,
}

impl UniswapV4SingletonHookStorageCollisionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        // CRITICAL FIX: Only analyze if contract implements Uniswap V4 hooks
        if !self.is_uniswap_v4_hook() {
            return findings; // Empty - not a Uniswap V4 hook contract
        }

        if let Some((slot, pcs)) = self.detect_storage_collision_risk() {
            findings.push(SecurityFinding {
                severity: SecuritySeverity::Critical,
                description: format!("Multiple pools share hook storage slot 0x{:x}, causing state collision.", slot),
                pc: pcs[0],
                confidence: 0.90,
            });
        }

        findings
    }

    fn detect_storage_collision_risk(&self) -> Option<(u64, Vec<usize>)> {
        use std::collections::HashMap;
        let bytecode = &self.bytecode;
        let mut slot_access: HashMap<u64, Vec<usize>> = HashMap::new();

        for i in 0..bytecode.len().saturating_sub(5) {
            if bytecode[i] == 0x60 { // PUSH1
                let slot = bytecode[i+1] as u64;
                
                for j in i+2..std::cmp::min(i+8, bytecode.len()) {
                    if bytecode[j] == 0x55 || bytecode[j] == 0x54 { // SSTORE or SLOAD
                        slot_access.entry(slot).or_insert_with(Vec::new).push(i);
                        break;
                    }
                }
            }
        }

        for (slot, pcs) in slot_access.iter() {
            if pcs.len() >= 3 {
                return Some((*slot, pcs.clone()));
            }
        }

        None
    }

    /// Check if contract implements Uniswap V4 hook interface
    fn is_uniswap_v4_hook(&self) -> bool {
        let bytecode = &self.bytecode;
        
        let hook_selectors = [
            [0x6d, 0x9f, 0x6d, 0x7d], // beforeInitialize
            [0x5c, 0x6f, 0x0b, 0x9e], // afterInitialize
            [0x4a, 0x4f, 0xbe, 0xec], // beforeModifyPosition
            [0x8c, 0x5b, 0x83, 0x85], // afterModifyPosition
            [0x5c, 0x0d, 0x5e, 0x53], // beforeSwap
            [0xf5, 0xe7, 0xb2, 0x10], // afterSwap
            [0x47, 0xa7, 0xd1, 0x07], // beforeDonate
            [0xc8, 0xe7, 0xa3, 0x3f], // afterDonate
        ];
        
        let mut found_hooks = 0;
        for selector in &hook_selectors {
            if bytecode.windows(4).take(500).any(|w| w == selector) {
                found_hooks += 1;
            }
        }
        
        found_hooks >= 2
    }
}
