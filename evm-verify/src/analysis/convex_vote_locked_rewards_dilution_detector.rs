use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvexVoteLockedVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ConvexVoteLockedRewardsDilutionDetector {
    bytecode: Vec<u8>,
}

impl ConvexVoteLockedRewardsDilutionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ConvexVoteLockedVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_vote_lock_reward_gaming());
        vulnerabilities.extend(self.detect_boost_calculation_manipulation());
        vulnerabilities.extend(self.detect_early_unlock_penalty_bypass());

        vulnerabilities
    }

    fn detect_vote_lock_reward_gaming(&self) -> Vec<ConvexVoteLockedVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x02 { // MUL (reward calculation with boost)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_lock_duration = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                let has_lock_amount = window.iter().any(|&b| b == 0x54); // SLOAD
                
                if has_lock_duration && has_lock_amount {
                    let has_snapshot_check = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    let has_average_lock = window.iter().any(|&b| b == 0x04); // DIV (averaging)
                    
                    if !has_snapshot_check {
                        vulns.push(ConvexVoteLockedVulnerability {
                            pc,
                            vulnerability_type: "VoteLockRewardGaming".to_string(),
                            description: format!(
                                "Convex vote-lock boost at PC {} uses instant lock state. Attack: observe upcoming reward distribution (e.g., CRV rewards), flashloan \
                                CVX tokens, lock for maximum duration just before reward snapshot, receive boosted rewards, unlock immediately after, return flashloan. \
                                Dilutes rewards for long-term lockers. Missing: time-weighted average lock calculation, minimum lock period before rewards, anti-gaming \
                                delay. Should use: average lock duration over epoch, not instant snapshot.",
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

    fn detect_boost_calculation_manipulation(&self) -> Vec<ConvexVoteLockedVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x04 { // DIV (boost calculation: locked / (staked + locked))
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_locked_balance = window.iter().filter(|&&b| b == 0x54).count() >= 2; // Multiple SLOAD
                let has_staked_balance = window.iter().filter(|&&b| b == 0x54).count() >= 3;
                
                if has_locked_balance && has_staked_balance {
                    let has_manipulation_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // Bounds check
                    let has_delta_limit = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if !has_delta_limit {
                        vulns.push(ConvexVoteLockedVulnerability {
                            pc,
                            vulnerability_type: "BoostCalculationManipulation".to_string(),
                            description: format!(
                                "Boost calculation at PC {} allows manipulation via stake/unstake. Convex boost = min(userLocked, userStaked * 2.5). Attack: user locks \
                                CVX for max boost, then repeatedly: (1) unstake all LP tokens, (2) claim rewards with low denominator = high boost, (3) restake LP tokens. \
                                Boost meant to reward proportional locking but can be gamed. Missing: stake/unstake cooldown, boost recalculation delay, minimum stake \
                                period. Should enforce: boost uses minimum(staked) over claim period, not instant value.",
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

    fn detect_early_unlock_penalty_bypass(&self) -> Vec<ConvexVoteLockedVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (unlock state)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_unlock_time_check = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                let has_penalty_calculation = window.iter().any(|&b| b == 0x02); // MUL (penalty)
                
                if has_unlock_time_check && has_penalty_calculation {
                    let has_penalty_recipient = window.iter().any(|&b| b == 0xF1); // CALL (send penalty)
                    let has_penalty_burn = window.iter().any(|&b| b == 0x03); // SUB (burn)
                    
                    if !has_penalty_recipient && !has_penalty_burn {
                        vulns.push(ConvexVoteLockedVulnerability {
                            pc,
                            vulnerability_type: "EarlyUnlockPenaltyBypass".to_string(),
                            description: format!(
                                "Early unlock penalty at PC {} doesn't properly handle penalty tokens. Convex charges penalty for early unlock (before lock expiry). \
                                Attack: penalty calculated but not enforced or distributed, attacker unlocks early without real penalty. Or: penalty goes to zero address, \
                                value destroyed instead of redistributed to long-term lockers. Missing: penalty distribution to remaining lockers, penalty validation, \
                                penalty burn verification. Should send penalty to: vlCVX holders or protocol treasury, not destroy value.",
                                pc
                            ),
                            confidence: 0.84,
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
}
