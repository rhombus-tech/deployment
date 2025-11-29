/// Known-Safe Pattern Database
/// Whitelists common protection mechanisms to reduce false positives

use std::collections::HashMap;

pub struct SafePatternDatabase {
    patterns: HashMap<String, SafePattern>,
}

#[derive(Clone)]
pub struct SafePattern {
    pub name: String,
    pub bytecode_signature: Vec<u8>,
    pub confidence_reduction: f32, // How much to reduce confidence (0.0-1.0)
    pub description: String,
}

impl SafePatternDatabase {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();
        
        // OpenZeppelin ReentrancyGuard
        patterns.insert("oz_reentrancy_guard".to_string(), SafePattern {
            name: "OpenZeppelin ReentrancyGuard".to_string(),
            bytecode_signature: vec![0x54, 0x60, 0x02, 0x14], // SLOAD, PUSH1 2, EQ
            confidence_reduction: 0.9, // 90% reduction
            description: "Standard ReentrancyGuard from OpenZeppelin".to_string(),
        });
        
        // Euler V2 EVC
        patterns.insert("euler_evc".to_string(), SafePattern {
            name: "Euler V2 EVC Deferred Checks".to_string(),
            bytecode_signature: vec![0x73, 0xFA], // PUSH20 (EVC addr), STATICCALL
            confidence_reduction: 0.95, // 95% reduction
            description: "Euler V2 Ethereum Vault Connector protection".to_string(),
        });
        
        // Checks-Effects-Interactions (CEI)
        patterns.insert("cei_pattern".to_string(), SafePattern {
            name: "Checks-Effects-Interactions".to_string(),
            bytecode_signature: vec![0x55, 0x55, 0xF1], // SSTORE, SSTORE, CALL
            confidence_reduction: 0.6, // 60% reduction
            description: "State changes before external calls".to_string(),
        });
        
        // Solidity 0.8+ built-in overflow protection
        patterns.insert("solc_0_8_math".to_string(), SafePattern {
            name: "Solidity 0.8+ SafeMath".to_string(),
            bytecode_signature: vec![0x01, 0x10, 0x15, 0x57], // ADD, LT, ISZERO, JUMPI
            confidence_reduction: 0.99, // 99% reduction - built-in
            description: "Built-in overflow checks in Solidity 0.8+".to_string(),
        });
        
        // SafeERC20 transfer check
        patterns.insert("safe_erc20".to_string(), SafePattern {
            name: "SafeERC20 Transfer".to_string(),
            bytecode_signature: vec![0xF1, 0x15, 0x57], // CALL, ISZERO, JUMPI
            confidence_reduction: 0.7, // 70% reduction
            description: "SafeERC20 checks transfer return value".to_string(),
        });

        Self { patterns }
    }
    
    pub fn matches(&self, bytecode: &[u8], pc: usize) -> Option<&SafePattern> {
        for pattern in self.patterns.values() {
            if self.matches_at(bytecode, pc, &pattern.bytecode_signature) {
                return Some(pattern);
            }
        }
        None
    }
    
    fn matches_at(&self, bytecode: &[u8], pc: usize, signature: &[u8]) -> bool {
        let search_start = pc.saturating_sub(50);
        let search_end = (pc + 50).min(bytecode.len());
        
        if search_end - search_start < signature.len() {
            return false;
        }
        
        bytecode[search_start..search_end]
            .windows(signature.len())
            .any(|window| window == signature)
    }
}
