use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LiquidityMiningType {
    RewardCalculationError,
    PoolDrainingVulnerability,
    RewardManipulation,
    StakingExploit,
    UnstakingExploit,
    RewardRateManipulation,
    EmergencyWithdrawAbuse,
    TimestampDependency,
    RewardOverflow,
    InsufficientRewardValidation,
    FlashLoanFarming,
    CompoundingError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidityMiningVulnerability {
    pub vulnerability_type: LiquidityMiningType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct LiquidityMiningAnalyzer {
    bytecode: Vec<u8>,
}

impl LiquidityMiningAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LiquidityMiningVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_reward_calculation_errors());
        vulnerabilities.extend(self.detect_pool_draining());
        vulnerabilities.extend(self.detect_reward_manipulation());
        vulnerabilities.extend(self.detect_staking_exploits());
        vulnerabilities.extend(self.detect_unstaking_exploits());
        vulnerabilities.extend(self.detect_flash_loan_farming());

        vulnerabilities
    }

    fn detect_staking_pattern(&self) -> bool {
        // Look for stake() or deposit() patterns
        let stake_sigs = [
            &[0xa6, 0x94, 0xfc, 0x3a][..], // stake()
            &[0xb6, 0xb5, 0x5f, 0x25][..], // deposit(uint256)
            &[0x47, 0xe7, 0xef, 0x24][..], // depositFor(address,uint256)
        ];

        stake_sigs.iter().any(|&sig| {
            self.bytecode.windows(sig.len()).any(|w| w == sig)
        })
    }

    fn detect_reward_calculation_errors(&self) -> Vec<LiquidityMiningVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.detect_staking_pattern() {
            return vulnerabilities;
        }

        // Look for getReward() or claimReward() functions
        let reward_sig = &[0x3d, 0x18, 0xb9, 0x12][..]; // getReward()
        
        if let Some(pos) = self.bytecode.windows(reward_sig.len()).position(|w| w == reward_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(100).min(self.bytecode.len())];
            
            // Check for multiplication without SafeMath or checked arithmetic
            let has_mul = function_section.contains(&0x02); // MUL opcode
            let has_div = function_section.contains(&0x04); // DIV opcode
            
            // Check for proper overflow protection
            let has_revert_check = function_section.windows(2).any(|w| {
                w[0] == 0x10 && w[1] == 0x57 // LT followed by JUMPI (overflow check)
            });

            if has_mul && !has_revert_check {
                vulnerabilities.push(LiquidityMiningVulnerability {
                    vulnerability_type: LiquidityMiningType::RewardCalculationError,
                    severity: SecuritySeverity::High,
                    location: pos,
                    description: "Reward calculation lacks overflow protection".to_string(),
                    exploit_scenario: "Attacker could manipulate reward calculation to claim excessive rewards through integer overflow".to_string(),
                    remediation: "Use SafeMath or Solidity 0.8+ checked arithmetic for all reward calculations".to_string(),
                });
            }

            // Check for timestamp dependency in reward calculation
            if function_section.contains(&0x42) { // TIMESTAMP
                vulnerabilities.push(LiquidityMiningVulnerability {
                    vulnerability_type: LiquidityMiningType::TimestampDependency,
                    severity: SecuritySeverity::Medium,
                    location: pos,
                    description: "Reward calculation depends on block.timestamp".to_string(),
                    exploit_scenario: "Miners can manipulate timestamps within ~15 second window to game rewards".to_string(),
                    remediation: "Use block numbers instead of timestamps, or add timestamp validation bounds".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_pool_draining(&self) -> Vec<LiquidityMiningVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for withdraw() or emergencyWithdraw() patterns
        let withdraw_sigs = [
            &[0x2e, 0x1a, 0x7d, 0x4d][..], // withdraw(uint256)
            &[0x5e, 0x82, 0xf9, 0xad][..], // emergencyWithdraw()
        ];

        for sig in &withdraw_sigs {
            if let Some(pos) = self.bytecode.windows(sig.len()).position(|w| w == *sig) {
                let function_section = &self.bytecode[pos..pos.saturating_add(80).min(self.bytecode.len())];
                
                // Check if there's a balance check before transfer
                let has_balance_check = function_section.windows(2).any(|w| {
                    w[0] == 0x54 && w[1] == 0x10 // SLOAD followed by LT (balance check)
                });

                // Check for CALL without balance validation
                let has_call = function_section.contains(&0xf1); // CALL

                if has_call && !has_balance_check {
                    vulnerabilities.push(LiquidityMiningVulnerability {
                        vulnerability_type: LiquidityMiningType::PoolDrainingVulnerability,
                        severity: SecuritySeverity::Critical,
                        location: pos,
                        description: "Withdrawal function lacks proper balance validation".to_string(),
                        exploit_scenario: "Attacker could drain pool by withdrawing more than their staked amount".to_string(),
                        remediation: "Add explicit balance checks: require(amount <= stakedBalance[msg.sender])".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_reward_manipulation(&self) -> Vec<LiquidityMiningVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for updateReward() or similar modifier patterns
        let update_sig = &[0x3c, 0x6b, 0x16, 0xab][..]; // Common updateReward modifier
        
        if let Some(pos) = self.bytecode.windows(update_sig.len()).position(|w| w == update_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(100).min(self.bytecode.len())];
            
            // Check for SSTORE without prior SLOAD (state manipulation)
            let sstore_count = function_section.iter().filter(|&&b| b == 0x55).count();
            let sload_count = function_section.iter().filter(|&&b| b == 0x54).count();

            if sstore_count > sload_count {
                vulnerabilities.push(LiquidityMiningVulnerability {
                    vulnerability_type: LiquidityMiningType::RewardManipulation,
                    severity: SecuritySeverity::High,
                    location: pos,
                    description: "Reward update function may allow manipulation".to_string(),
                    exploit_scenario: "Attacker could manipulate reward rates or accumulated rewards directly".to_string(),
                    remediation: "Ensure reward updates validate previous state and use proper access control".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_staking_exploits(&self) -> Vec<LiquidityMiningVulnerability> {
        let mut vulnerabilities = Vec::new();

        let stake_sig = &[0xa6, 0x94, 0xfc, 0x3a][..]; // stake()
        
        if let Some(pos) = self.bytecode.windows(stake_sig.len()).position(|w| w == stake_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(100).min(self.bytecode.len())];
            
            // Check for reentrancy protection
            let has_reentrancy_guard = function_section.windows(3).any(|w| {
                w[0] == 0x54 && // SLOAD
                w[1] == 0x15 && // ISZERO
                w[2] == 0x57    // JUMPI (checking locked flag)
            });

            if !has_reentrancy_guard {
                vulnerabilities.push(LiquidityMiningVulnerability {
                    vulnerability_type: LiquidityMiningType::StakingExploit,
                    severity: SecuritySeverity::High,
                    location: pos,
                    description: "Staking function lacks reentrancy protection".to_string(),
                    exploit_scenario: "Attacker could recursively call stake() to manipulate balances or rewards".to_string(),
                    remediation: "Add nonReentrant modifier or checks-effects-interactions pattern".to_string(),
                });
            }

            // Check for zero amount validation
            let has_zero_check = function_section.windows(2).any(|w| {
                w[0] == 0x15 && w[1] == 0x57 // ISZERO JUMPI (require amount > 0)
            });

            if !has_zero_check {
                vulnerabilities.push(LiquidityMiningVulnerability {
                    vulnerability_type: LiquidityMiningType::InsufficientRewardValidation,
                    severity: SecuritySeverity::Medium,
                    location: pos,
                    description: "Staking function doesn't validate zero amounts".to_string(),
                    exploit_scenario: "Users could stake zero tokens to game reward distribution".to_string(),
                    remediation: "Add require(amount > 0) check at function start".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_unstaking_exploits(&self) -> Vec<LiquidityMiningVulnerability> {
        let mut vulnerabilities = Vec::new();

        let withdraw_sig = &[0x2e, 0x1a, 0x7d, 0x4d][..]; // withdraw(uint256)
        
        if let Some(pos) = self.bytecode.windows(withdraw_sig.len()).position(|w| w == withdraw_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(100).min(self.bytecode.len())];
            
            // Check for state update before external call (CEI pattern)
            let sstore_pos = function_section.iter().position(|&b| b == 0x55); // SSTORE
            let call_pos = function_section.iter().position(|&b| b == 0xf1); // CALL

            if let (Some(store), Some(call)) = (sstore_pos, call_pos) {
                if call < store {
                    vulnerabilities.push(LiquidityMiningVulnerability {
                        vulnerability_type: LiquidityMiningType::UnstakingExploit,
                        severity: SecuritySeverity::Critical,
                        location: pos,
                        description: "Unstaking uses incorrect checks-effects-interactions order".to_string(),
                        exploit_scenario: "Reentrancy attack possible - attacker can withdraw same funds multiple times".to_string(),
                        remediation: "Update state (SSTORE) before external calls (CALL). Follow CEI pattern".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_flash_loan_farming(&self) -> Vec<LiquidityMiningVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for patterns that suggest instant deposit+withdraw in same transaction
        let stake_sig = &[0xa6, 0x94, 0xfc, 0x3a][..]; // stake()
        let withdraw_sig = &[0x2e, 0x1a, 0x7d, 0x4d][..]; // withdraw()
        
        let has_stake = self.bytecode.windows(stake_sig.len()).any(|w| w == stake_sig);
        let has_withdraw = self.bytecode.windows(withdraw_sig.len()).any(|w| w == withdraw_sig);

        if has_stake && has_withdraw {
            // Check if there's minimum staking time enforcement
            let has_time_lock = self.bytecode.windows(5).any(|w| {
                w[0] == 0x42 && // TIMESTAMP
                w[1] == 0x54 && // SLOAD (last stake time)
                w[2] == 0x03 && // SUB
                w[3] == 0x10    // LT (check if enough time passed)
            });

            if !has_time_lock {
                vulnerabilities.push(LiquidityMiningVulnerability {
                    vulnerability_type: LiquidityMiningType::FlashLoanFarming,
                    severity: SecuritySeverity::High,
                    location: 0,
                    description: "No minimum staking period - vulnerable to flash loan attacks".to_string(),
                    exploit_scenario: "Attacker uses flash loan to stake huge amount, claim rewards, and unstake in same tx".to_string(),
                    remediation: "Implement minimum staking period (e.g., 1 block) or use snapshot-based rewards".to_string(),
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
    fn test_detect_staking_pattern() {
        let bytecode = vec![
            0x60, 0x00, 0xa6, 0x94, 0xfc, 0x3a, // stake() signature
            0x02, 0x04, // MUL, DIV
        ];
        
        let analyzer = LiquidityMiningAnalyzer::new(bytecode);
        assert!(analyzer.detect_staking_pattern());
    }

    #[test]
    fn test_reward_calculation_vulnerability() {
        let bytecode = vec![
            0x3d, 0x18, 0xb9, 0x12, // getReward() signature
            0x02, // MUL without overflow check
            0xf1, // CALL
        ];
        
        let analyzer = LiquidityMiningAnalyzer::new(bytecode);
        let vulns = analyzer.detect_reward_calculation_errors();
        assert!(!vulns.is_empty());
    }

    #[test]
    fn test_pool_draining_detection() {
        let bytecode = vec![
            0x2e, 0x1a, 0x7d, 0x4d, // withdraw() signature
            0xf1, // CALL without balance check
        ];
        
        let analyzer = LiquidityMiningAnalyzer::new(bytecode);
        let vulns = analyzer.detect_pool_draining();
        assert!(!vulns.is_empty());
    }
}
