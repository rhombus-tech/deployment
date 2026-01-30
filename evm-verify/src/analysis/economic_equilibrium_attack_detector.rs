use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EconomicEquilibriumVulnerability {
    NashEquilibriumManipulation { description: String, location: usize, confidence: f32 },
    RationalValidatorAttack { description: String, location: usize, confidence: f32 },
    IncentiveMisalignment { description: String, location: usize, confidence: f32 },
    ZeroSumGameExploit { description: String, location: usize, confidence: f32 },
}

pub struct EconomicEquilibriumAttackDetector {
    bytecode: Vec<u8>,
}

impl EconomicEquilibriumAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<EconomicEquilibriumVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Nash Equilibrium: When rational actors have dominant strategy that harms protocol
        // Example: In staking, it's always rational to NOT validate (save costs) if others validate
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            let section = &self.bytecode[i..std::cmp::min(i + 100, self.bytecode.len())];
            
            // Pattern 1: Reward distribution without minimum participation check
            let has_reward_calc = section.windows(12).any(|w| {
                w.contains(&0x54) && // SLOAD (total staked)
                w.contains(&0x04) && // DIV (reward per share)
                w.contains(&0x02)    // MUL (user reward)
            });
            
            let no_min_participation = !section.windows(10).any(|w| {
                w.contains(&0x10) && // LT (check minimum)
                w.contains(&0x57)    // JUMPI (enforce)
            });
            
            if has_reward_calc && no_min_participation {
                vulnerabilities.push(EconomicEquilibriumVulnerability::NashEquilibriumManipulation {
                    description: format!("Nash equilibrium attack at PC {}. Protocol rewards distributed regardless of participation level. Rational strategy: Free-ride on others' work. Example: Staking protocol where 1 validator gets same rewards as 100 validators → everyone stops validating. Or: DAO where voting costs gas but outcome affects everyone → nobody votes. Fix: Require minimum participation threshold (e.g., 10% quorum), or participation-weighted rewards.", i),
                    location: i,
                    confidence: 0.83,
                });
            }
            
            // Pattern 2: Validator selection without penalty for non-participation
            let has_validator_selection = section.windows(15).any(|w| {
                w.contains(&0x54) && // SLOAD (validator list)
                w.contains(&0x20) && // SHA3 (random selection)
                w.contains(&0x55)    // SSTORE (assign duty)
            });
            
            let no_penalty = !section.windows(8).any(|w| {
                w.contains(&0x03) && // SUB (slash stake)
                w.contains(&0x55)    // SSTORE (apply penalty)
            });
            
            if has_validator_selection && no_penalty {
                vulnerabilities.push(EconomicEquilibriumVulnerability::RationalValidatorAttack {
                    description: format!("Rational validator attack at PC {}. Validators selected for duty but no penalty for not performing. Rational behavior: Register as validator, never validate, keep earning. Example: Rocket Pool minipool operator registers but never validates → still gets rewards. Or: Oracle network where reporters can skip reports with no penalty. Fix: Slash stake for missed duties, reputation system, or require continuous performance proof.", i),
                    location: i,
                    confidence: 0.86,
                });
            }
            
            // Pattern 3: Incentive structure where cost > benefit
            let has_cost_benefit_calc = section.windows(20).any(|w| {
                w.contains(&0x02) && // MUL (calculate reward)
                w.contains(&0x5A) && // GAS (check cost)
                w.contains(&0x04)    // DIV (compare)
            });
            
            if has_cost_benefit_calc {
                // Check if reward < cost is possible
                let potential_negative = section.windows(8).any(|w| {
                    w.contains(&0x10) && w.contains(&0x03) // LT + SUB (reward < cost)
                });
                
                if potential_negative {
                    vulnerabilities.push(EconomicEquilibriumVulnerability::IncentiveMisalignment {
                        description: format!("Incentive misalignment at PC {}. Action costs more than reward at equilibrium. Example: Claiming rewards costs 50k gas ($10) but reward is $5 → nobody claims → funds locked. Or: Liquidation costs $100 gas, profit $50 → no liquidators → protocol becomes insolvent. Or: Governance vote costs $20 gas, no personal benefit → nobody votes → DAO paralyzed. Fix: Ensure reward > cost * 2 (safety margin), subsidize critical operations, or batch operations to amortize costs.", i),
                        location: i,
                        confidence: 0.88,
                    });
                }
            }
            
            // Pattern 4: Zero-sum game where attacking is profitable
            let has_competitive_reward = section.windows(15).any(|w| {
                w.contains(&0x54) && // SLOAD (total rewards)
                w.contains(&0x04) && // DIV (split among users)
                w.contains(&0x03)    // SUB (one user's gain = others' loss)
            });
            
            if has_competitive_reward {
                vulnerabilities.push(EconomicEquilibriumVulnerability::ZeroSumGameExploit {
                    description: format!("Zero-sum game exploit at PC {}. Fixed reward pool split among participants → attacking others increases your share. Examples: 1) Oracle network: Submit wrong data to disqualify others → larger share. 2) Liquidity mining: Grief other LPs to get more rewards. 3) NFT mint: DOS others to mint more. 4) Auction: Prevent others from bidding. Equilibrium: Everyone attacks everyone → system collapses. Fix: Punish attackers more than they gain, or make rewards non-zero-sum (growing pie, not fixed).", i),
                    location: i,
                    confidence: 0.81,
                });
            }
        }
        
        vulnerabilities
    }
}
