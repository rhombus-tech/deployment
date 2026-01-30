/// Unclaimed Yield/Reward Forfeiture Detector
///
/// Detects vulnerabilities in reward claiming mechanisms where unclaimed
/// rewards can be forfeited, expire, or be stolen.
///
/// Real-world impact:
/// - $10M+ in unclaimed/forfeited rewards across DeFi
/// - Compound unclaimed COMP tokens
/// - Synthetix expired staking rewards
/// - Liquidity mining programs with expiration

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardForfeitureVulnerability {
    pub vulnerability_type: RewardForfeitureType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RewardForfeitureType {
    UnclaimedRewardExpiration,      // Rewards expire if not claimed
    RewardOverwrite,                // New rewards overwrite unclaimed
    ClaimDeadlineBypass,            // Deadline can be manipulated
    AccruedRewardLoss,              // Accrued rewards lost on exit
    RewardRoundingToZero,           // Small rewards round to zero
    AdminRewardSweep,               // Admin can sweep unclaimed
    RewardCalculationStale,         // Stale reward calculation
    MissedRewardPeriod,             // Missing a claim period forfeits all
    RewardTokenSwap,                // Reward token changed, old lost
    CompoundingFailure,             // Auto-compound fails, rewards lost
}

pub struct RewardForfeitureDetector {
    bytecode: Vec<u8>,
}

impl RewardForfeitureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<RewardForfeitureVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        vulnerabilities.extend(self.detect_reward_expiration());
        vulnerabilities.extend(self.detect_reward_overwrite());
        vulnerabilities.extend(self.detect_admin_reward_sweep());
        vulnerabilities.extend(self.detect_accrued_reward_loss());
        
        vulnerabilities
    }
    
    fn detect_reward_expiration(&self) -> Vec<RewardForfeitureVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: Reward storage with timestamp but no claim before expiry
        for i in 0..self.bytecode.len().saturating_sub(30) {
            let mut has_reward_storage = false;
            let mut has_timestamp_check = false;
            let mut has_expiry_check = false;
            
            for j in i..self.bytecode.len().min(i + 30) {
                if self.bytecode[j] == 0x55 { // SSTORE
                    has_reward_storage = true;
                }
                if self.bytecode[j] == 0x42 { // TIMESTAMP
                    has_timestamp_check = true;
                }
                if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT/GT
                    if has_timestamp_check {
                        has_expiry_check = true;
                    }
                }
            }
            
            if has_reward_storage && has_timestamp_check && has_expiry_check {
                vulnerabilities.push(RewardForfeitureVulnerability {
                    vulnerability_type: RewardForfeitureType::UnclaimedRewardExpiration,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Rewards have expiration timestamp. Unclaimed rewards after deadline \
                                may be forfeited or become unclaimable.".to_string(),
                    exploit_scenario: "1. User stakes 100 ETH in liquidity mining program\n\
                                      2. Earns 10 ETH in rewards over 6 months\n\
                                      3. Claim deadline is 30 days after program ends\n\
                                      4. User forgets to claim within deadline\n\
                                      5. After deadline, claimRewards() reverts\n\
                                      6. 10 ETH permanently lost\n\
                                      7. Or worse: admin can sweep to treasury\n\
                                      8. $10M+ in unclaimed rewards across DeFi\n\
                                      9. Real example: Compound unclaimed COMP tokens\n\
                                      10. Users lose earned rewards due to deadline".to_string(),
                    recommendation: "Remove reward expiration or add grace period. Allow claims indefinitely. \
                                  Emit warnings before expiry. Auto-claim on unstake. Add reward rescue function \
                                  for users. Consider perpetual claiming window.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
    
    fn detect_reward_overwrite(&self) -> Vec<RewardForfeitureVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: Reward update without claiming previous
        for i in 0..self.bytecode.len().saturating_sub(20) {
            let mut updates_reward = false;
            let mut checks_unclaimed = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                if self.bytecode[j] == 0x55 { // SSTORE
                    updates_reward = true;
                }
                if self.bytecode[j] == 0x54 { // SLOAD (checking old value)
                    if j + 1 < self.bytecode.len() && self.bytecode[j+1] == 0x15 { // ISZERO
                        checks_unclaimed = true;
                    }
                }
            }
            
            if updates_reward && !checks_unclaimed {
                vulnerabilities.push(RewardForfeitureVulnerability {
                    vulnerability_type: RewardForfeitureType::RewardOverwrite,
                    severity: "Medium".to_string(),
                    location: vec![i],
                    description: "Reward calculation overwrites previous unclaimed rewards without \
                                accumulation or claim check.".to_string(),
                    exploit_scenario: "1. User has 5 ETH unclaimed rewards\n\
                                      2. Reward calculation runs again\n\
                                      3. New rewards = 3 ETH\n\
                                      4. storage[user] = 3 ETH (overwrites 5 ETH)\n\
                                      5. User permanently loses 5 ETH\n\
                                      6. Only can claim 3 ETH now\n\
                                      7. Happens on every reward update\n\
                                      8. $1M+ lost to reward overwrites".to_string(),
                    recommendation: "Accumulate rewards: newRewards = oldRewards + calculated. \
                                  Or require claim before update. Add reward history tracking. \
                                  Emit events on reward updates. Protect unclaimed amounts.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
    
    fn detect_admin_reward_sweep(&self) -> Vec<RewardForfeitureVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: Admin function that can sweep rewards
        for i in 0..self.bytecode.len().saturating_sub(25) {
            let mut has_admin_check = false;
            let mut transfers_tokens = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                if self.bytecode[j] == 0x33 { // CALLER
                    if j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x14 { // EQ
                        has_admin_check = true;
                    }
                }
                if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xFA { // CALL/STATICCALL
                    transfers_tokens = true;
                }
            }
            
            if has_admin_check && transfers_tokens {
                vulnerabilities.push(RewardForfeitureVulnerability {
                    vulnerability_type: RewardForfeitureType::AdminRewardSweep,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Admin can sweep/withdraw reward tokens, potentially including \
                                user unclaimed rewards.".to_string(),
                    exploit_scenario: "1. 1000 users have unclaimed rewards totaling 500 ETH\n\
                                      2. Admin calls sweepUnclaimedRewards()\n\
                                      3. Transfers 500 ETH to admin wallet\n\
                                      4. Users try to claim → transaction reverts (insufficient balance)\n\
                                      5. All unclaimed rewards stolen by admin\n\
                                      6. $5M+ rug pull via reward sweep\n\
                                      7. Or 'legitimate' cleanup becomes theft".to_string(),
                    recommendation: "Separate user rewards from protocol reserves. Track per-user \
                                  claimable amounts. Only allow sweeping truly abandoned rewards \
                                  (1+ year unclaimed). Require governance vote. Add timelocks. \
                                  Never touch active user rewards.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
    
    fn detect_accrued_reward_loss(&self) -> Vec<RewardForfeitureVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: Exit/unstake without claiming accrued rewards
        for i in 0..self.bytecode.len().saturating_sub(20) {
            let mut performs_exit = false;
            let mut claims_rewards = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                // Exit (balance reduction)
                if self.bytecode[j] == 0x03 { // SUB
                    if j + 1 < self.bytecode.len() && self.bytecode[j+1] == 0x55 { // SSTORE
                        performs_exit = true;
                    }
                }
                // Reward claim/transfer
                if self.bytecode[j] == 0xF1 { // CALL (token transfer)
                    claims_rewards = true;
                }
            }
            
            if performs_exit && !claims_rewards {
                vulnerabilities.push(RewardForfeitureVulnerability {
                    vulnerability_type: RewardForfeitureType::AccruedRewardLoss,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "User exit/unstake does not automatically claim accrued rewards. \
                                Rewards may be lost on withdrawal.".to_string(),
                    exploit_scenario: "1. User stakes for 12 months, earns 20 ETH rewards\n\
                                      2. Calls unstake() to withdraw principal\n\
                                      3. Unstake succeeds, returns principal\n\
                                      4. But doesn't claim/transfer 20 ETH rewards\n\
                                      5. Reward counter reset on unstake\n\
                                      6. User loses 20 ETH permanently\n\
                                      7. Thought rewards auto-claimed\n\
                                      8. $2M+ lost to unstake without claim".to_string(),
                    recommendation: "Auto-claim rewards on unstake: claimRewards(); unstake();. \
                                  Or clearly document manual claim requirement. Add claim reminder. \
                                  Preserve unclaimed rewards even after exit. Add safety warnings in UI.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_reward_expiration() {
        let bytecode = vec![
            0x55, // SSTORE (reward storage)
            0x42, // TIMESTAMP
            0x10, // LT (expiry check)
        ];
        
        let detector = RewardForfeitureDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            RewardForfeitureType::UnclaimedRewardExpiration
        )));
    }
    
    #[test]
    fn test_reward_overwrite() {
        let bytecode = vec![
            0x55, // SSTORE (no SLOAD check)
        ];
        
        let detector = RewardForfeitureDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            RewardForfeitureType::RewardOverwrite
        )));
    }
}
