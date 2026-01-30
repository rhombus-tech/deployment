use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EraLendVulnerability {
    ZkSyncReadonlyReentrancy { description: String, location: usize, confidence: f32 },
    ZkSyncHookTimingExploit { description: String, location: usize, confidence: f32 },
}

pub struct EraLendZkSyncReadonlyReentrancyDetector {
    bytecode: Vec<u8>,
}

impl EraLendZkSyncReadonlyReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<EraLendVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // EraLend on zkSync Era: April 2024 $3.4M exploit
        // zkSync has different hook timing vs other L2s
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            let section = &self.bytecode[i..std::cmp::min(i + 100, self.bytecode.len())];
            
            // Pattern: External view function reading state during state change
            let has_view_call = section.windows(10).any(|w| {
                w.contains(&0xFA) && // STATICCALL (view function)
                w.contains(&0x54)    // SLOAD (read balances)
            });
            
            let has_state_change = section.windows(8).any(|w| {
                w.contains(&0xF1) && // CALL (external)
                w.contains(&0x55)    // SSTORE (state update)
            });
            
            let no_reentrancy_guard = !section.contains(&0x02); // No status flag pattern
            
            if has_view_call && has_state_change && no_reentrancy_guard {
                vulnerabilities.push(EraLendVulnerability::ZkSyncReadonlyReentrancy {
                    description: format!("zkSync readonly reentrancy at PC {}. EraLend April 2024: $3.4M. zkSync Era specifics: 1) Hook execution BEFORE balance update (different from ETH mainnet), 2) View function reads old balance, 3) Calculation wrong. Attack: 1) Deposit to lending market, 2) During deposit hook (before balance update), 3) Call getAccountLiquidity() → returns old balance, 4) Borrow based on inflated collateral. zkSync-specific: Hook timing different from Optimism/Arbitrum. Mitigation: Reentrancy guard on ALL functions (even views), finalize state before external calls.", i),
                    location: i,
                    confidence: 0.91,
                });
            }
            
            // Pattern: zkSync-specific hook without completion check
            let has_zksync_hook = section.windows(12).any(|w| {
                w.contains(&0xF1) && // CALL (to token)
                w.contains(&0x3D) && // RETURNDATASIZE
                w.contains(&0x3E)    // RETURNDATACOPY
            });
            
            if has_zksync_hook && !section.contains(&0x14) { // No EQ check for completion
                vulnerabilities.push(EraLendVulnerability::ZkSyncHookTimingExploit {
                    description: format!("zkSync hook timing exploit at PC {}. zkSync Era uses different EVM semantics: 1) Hooks execute at different points vs mainnet, 2) Native token transfers have hooks, 3) Reentrancy patterns differ. Attack vector: Exploit timing assumption that state is final before hook. Example: Transfer token → hook called → state not yet updated → read stale state → exploit. Mitigation: Assume ALL external calls (including transfers) can reenter, use checks-effects-interactions strictly, test on zkSync testnet (not just mainnet fork).", i),
                    location: i,
                    confidence: 0.85,
                });
            }
        }
        
        vulnerabilities
    }
}
