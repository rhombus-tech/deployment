use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BalancerVaultReentrancyVulnerability {
    ReadOnlyReentrancy { description: String, location: usize, confidence: f32 },
    GetPoolTokensNotProtected { description: String, location: usize },
    ViewFunctionReentrancy { description: String, location: usize },
}

pub struct BalancerVaultReentrancyDetector {
    bytecode: Vec<u8>,
}

impl BalancerVaultReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BalancerVaultReentrancyVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Balancer read-only reentrancy: view functions can be reentered
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_vault_view_function(i) {
                if !self.has_reentrancy_guard_on_view(i, i + 100) {
                    vulnerabilities.push(BalancerVaultReentrancyVulnerability::ViewFunctionReentrancy {
                        description: "Vault view function without reentrancy guard - read-only reentrancy risk".to_string(),
                        location: i,
                    });
                }
            }
            
            if self.is_get_pool_tokens_call(i) {
                if !self.validates_vault_state(i, i + 100) {
                    vulnerabilities.push(BalancerVaultReentrancyVulnerability::GetPoolTokensNotProtected {
                        description: "getPoolTokens() call without vault state validation - manipulable during reentrancy".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_vault_view_function(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        // Common Balancer view functions
        // getPoolTokens: 0xf94d4668
        // getPool: 0x29b9e8d6
        let selectors = [
            [0xf9, 0x4d, 0x46, 0x68],
            [0x29, 0xb9, 0xe8, 0xd6],
        ];
        
        selectors.iter().any(|sel| {
            self.bytecode[location..location + 20].windows(4).any(|w| w == sel)
        })
    }
    
    fn has_reentrancy_guard_on_view(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // View functions should check vault lock state
        // Pattern: SLOAD lock slot + ISZERO + REVERT
        let has_lock_read = self.bytecode[start..range_end].iter().any(|&b| b == 0x54);
        let has_check = self.bytecode[start..range_end].iter().any(|&b| b == 0x15);
        
        has_lock_read && has_check
    }
    
    fn is_get_pool_tokens_call(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        self.bytecode[location..location + 20]
            .windows(4)
            .any(|w| w == [0xf9, 0x4d, 0x46, 0x68])
    }
    
    fn validates_vault_state(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Should validate vault is not in callback
        self.bytecode[start..range_end].windows(3).any(|w| {
            w[0] == 0x54 && w[1] == 0x15 && w[2] == 0xFD // SLOAD + ISZERO + REVERT
        })
    }
}
