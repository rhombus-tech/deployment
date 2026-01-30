use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmergentMultiProtocolVulnerability {
    ComposabilityEdgeCase { description: String, location: usize, confidence: f32 },
    ProtocolInteractionConflict { description: String, location: usize, confidence: f32 },
}

pub struct EmergentMultiProtocolBugDetector {
    bytecode: Vec<u8>,
}

impl EmergentMultiProtocolBugDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<EmergentMultiProtocolVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Emergent bugs: A+B+C together creates vulnerability, but each alone is safe
        
        for i in 0..self.bytecode.len().saturating_sub(120) {
            let section = &self.bytecode[i..std::cmp::min(i + 120, self.bytecode.len())];
            
            // Pattern 1: Multiple external calls with state assumptions
            let call_count = section.windows(6).filter(|w| w.contains(&0xF1) || w.contains(&0xFA)).count();
            
            if call_count >= 3 {
                // Multiple protocols interacting
                let has_state_assumption = section.windows(10).any(|w| {
                    w.contains(&0x54) && // SLOAD (check state)
                    w.contains(&0x14)    // EQ (assume value)
                });
                
                if has_state_assumption {
                    vulnerabilities.push(EmergentMultiProtocolVulnerability::ComposabilityEdgeCase {
                        description: format!("Composability edge case at PC {}. Contract calls 3+ external protocols and assumes state. Emergent bugs: 1) Aave + Compound + Curve: Deposit to Aave, use receipt as collateral in Compound, stake in Curve → each protocol safe alone, together creates re-collateralization → infinite leverage. 2) Uniswap + flash loan + governance: Flash loan tokens → vote in governance → pass proposal → repay loan → governance assumes token holders are long-term aligned. 3) ERC4626 vault + leverage protocol + rebasing token: Deposit rebasing token to vault → vault shares increase → use shares as collateral → rebasing increases → shares increase → infinite collateral. Each protocol checks its own invariants, but combination breaks global invariant. Mitigation: Test all protocol combinations, add re-entrancy guards across protocols, or limit composability depth.", i),
                        location: i,
                        confidence: 0.79,
                    });
                }
            }
            
            // Pattern 2: Conflicting protocol assumptions
            let has_balance_check = section.windows(8).any(|w| {
                w.contains(&0x31) && // BALANCE (check ETH)
                w.contains(&0x10)    // LT (validate)
            });
            
            let has_token_transfer = section.windows(10).any(|w| {
                w.contains(&0xF1) && // CALL (transfer)
                w.contains(&0x35)    // CALLDATALOAD (amount)
            });
            
            if has_balance_check && has_token_transfer {
                vulnerabilities.push(EmergentMultiProtocolVulnerability::ProtocolInteractionConflict {
                    description: format!("Protocol interaction conflict at PC {}. Contract interacts with multiple tokens/protocols with different assumptions. Examples: 1) Fee-on-transfer token + DEX: DEX assumes balance increases by X after transfer, but fee-on-transfer only increases by 0.9X → accounting mismatch → economic exploit. 2) Rebasing token + lending: Lender assumes collateral value constant, but rebase changes balance → liquidation threshold violated. 3) Oracle price + AMM price: Contract uses Chainlink for one asset, Uniswap TWAP for another → attacker manipulates TWAP, protocol thinks prices are consistent → arb. 4) Pausable token + DeFi: Protocol assumes token always transferable, but token gets paused → protocol locks up. Fix: Explicitly handle each token type (fee-on-transfer, rebasing, pausable), verify assumptions at each interaction boundary, or whitelist compatible protocols only.", i),
                    location: i,
                    confidence: 0.81,
                });
            }
        }
        
        vulnerabilities
    }
}
