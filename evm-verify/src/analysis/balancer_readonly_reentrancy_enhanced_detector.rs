use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BalancerReadOnlyReentrancyVulnerability {
    LPTokenPriceManipulation { description: String, location: usize, confidence: f32 },
    VaultContextMutation { description: String, location: usize, confidence: f32 },
    MissingReentrancyGuard { description: String, location: usize, confidence: f32 },
    UnsafeGetPoolTokens { description: String, location: usize, confidence: f32 },
}

pub struct BalancerReadOnlyReentrancyEnhancedDetector {
    bytecode: Vec<u8>,
}

impl BalancerReadOnlyReentrancyEnhancedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<BalancerReadOnlyReentrancyVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_lp_price_manipulation());
        vulnerabilities.extend(self.detect_vault_context_mutation());
        vulnerabilities.extend(self.detect_unsafe_pool_queries());
        vulnerabilities
    }
    
    fn detect_lp_price_manipulation(&self) -> Vec<BalancerReadOnlyReentrancyVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if i + 150 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 150];
                let reads_lp_price = section.windows(4).any(|w| {
                    w == &[0xf8, 0x77, 0xa6, 0x1c] || w == &[0xba, 0x08, 0x76, 0x52]
                });
                let no_reentrancy_check = !section.windows(8).any(|w| {
                    w.contains(&0x54) && w.contains(&0x15) && w.contains(&0xFD)
                });
                let uses_for_collateral = section.contains(&0x02) || section.contains(&0x04);
                if reads_lp_price && no_reentrancy_check && uses_for_collateral {
                    vulnerabilities.push(BalancerReadOnlyReentrancyVulnerability::LPTokenPriceManipulation {
                        description: format!("LP token price read at PC {} vulnerable to read-only reentrancy. Sentiment exploit ($1M): During Balancer vault swap, attacker reenters lending protocol via ETH transfer → reads manipulated LP price → borrows more than allowed. Must use VaultReentrancyLib.ensureNotInVaultContext().", i),
                        location: i,
                        confidence: 0.95,
                    });
                }
            }
        }
        vulnerabilities
    }
    
    fn detect_vault_context_mutation(&self) -> Vec<BalancerReadOnlyReentrancyVulnerability> {
        let mut vulnerabilities = Vec::new();
        let balancer_vault_sigs = [&[0x8b, 0xff, 0x20, 0xc6][..], &[0x52, 0xf7, 0xc5, 0xf3][..]];
        for sig in &balancer_vault_sigs {
            for i in 0..self.bytecode.len().saturating_sub(4) {
                if &self.bytecode[i..i + 4] == *sig {
                    let section = &self.bytecode[i..std::cmp::min(i + 200, self.bytecode.len())];
                    let has_external_call = section.contains(&0xF1);
                    let checks_vault_context = section.windows(4).any(|w| w == &[0xe1, 0x5e, 0x7d, 0xfe]);
                    if has_external_call && !checks_vault_context {
                        vulnerabilities.push(BalancerReadOnlyReentrancyVulnerability::VaultContextMutation {
                            description: format!("Balancer vault interaction at PC {} allows reentrancy during state mutation. Between token transfer and balance update, vault state is inconsistent. Any view function called during this window returns wrong values. Add manageUserBalance() protection.", i),
                            location: i,
                            confidence: 0.92,
                        });
                    }
                }
            }
        }
        vulnerabilities
    }
    
    fn detect_unsafe_pool_queries(&self) -> Vec<BalancerReadOnlyReentrancyVulnerability> {
        let mut vulnerabilities = Vec::new();
        let query_sigs = [&[0xf9, 0x4d, 0x46, 0x68][..], &[0x6a, 0xf7, 0x86, 0x3f][..]];
        for sig in &query_sigs {
            for i in 0..self.bytecode.len().saturating_sub(4) {
                if &self.bytecode[i..i + 4] == *sig {
                    let section = &self.bytecode[i..std::cmp::min(i + 120, self.bytecode.len())];
                    let in_fallback = i > 100 && self.bytecode[i - 100..i].contains(&0x00);
                    let no_reentrancy_lock = !section.windows(5).any(|w| {
                        w.contains(&0x54) && w.contains(&0x15)
                    });
                    if in_fallback && no_reentrancy_lock {
                        vulnerabilities.push(BalancerReadOnlyReentrancyVulnerability::UnsafeGetPoolTokens {
                            description: format!("Pool query at PC {} callable during reentrancy (via fallback). getPoolTokens() and similar view functions return stale data during swaps. Use: vault.getPoolTokens() only after ensureNotInVaultContext() check.", i),
                            location: i,
                            confidence: 0.89,
                        });
                    }
                }
            }
        }
        vulnerabilities
    }
}
