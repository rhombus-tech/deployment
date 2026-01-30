/// Multi-Token Reward Accounting Detector
/// Detects bugs in protocols with multiple reward tokens (Aave, Compound, Convex style)

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiTokenRewardVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

pub struct MultiTokenRewardAccountingDetector {
    bytecode: Vec<u8>,
}

impl MultiTokenRewardAccountingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MultiTokenRewardVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_reward_index_manipulation());
        vulnerabilities.extend(self.detect_unchecked_reward_claim());
        vulnerabilities.extend(self.detect_reward_reentrancy());
        vulnerabilities
    }

    fn detect_reward_index_manipulation(&self) -> Vec<MultiTokenRewardVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            if self.is_reward_calculation(pc) {
                if !self.has_index_update_protection(pc, 150) {
                    vulnerabilities.push(MultiTokenRewardVulnerability {
                        severity: SecuritySeverity::Critical,
                        confidence: 0.85,
                        description: format!(
                            "Multi-token reward calculation at PC {} doesn't properly update reward indexes. \
                            Attacker can claim rewards multiple times across different tokens.",
                            pc
                        ),
                        exploit_scenario:
                            "Reward Index Attack:\n\
                             1. Protocol has 3 reward tokens: TOKEN_A, TOKEN_B, TOKEN_C\n\
                             2. User stakes 100 tokens\n\
                             3. Reward index for TOKEN_A updates\n\
                             4. User claims TOKEN_A rewards\n\
                             5. Reward indexes for TOKEN_B and TOKEN_C not properly tracked\n\
                             6. User unstakes and restakes to reset position\n\
                             7. User claims TOKEN_B and TOKEN_C rewards again\n\
                             8. Protocol loses rewards due to double counting\n\n\
                             Fix: Track per-token reward indexes separately:\n\
                             mapping(address => mapping(address => uint256)) public userRewardIndex;\n\
                             mapping(address => uint256) public globalRewardIndex;\n\
                             \n\
                             function claimReward(address rewardToken) {\n\
                                 uint256 pending = (globalRewardIndex[rewardToken] - userRewardIndex[msg.sender][rewardToken]) \n\
                                     * userBalance[msg.sender] / 1e18;\n\
                                 userRewardIndex[msg.sender][rewardToken] = globalRewardIndex[rewardToken];\n\
                                 rewardToken.transfer(msg.sender, pending);\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_unchecked_reward_claim(&self) -> Vec<MultiTokenRewardVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(250) {
            if self.is_transfer_call(pc) && self.has_multiple_reward_tokens(pc, 300) {
                if !self.has_balance_check_before_transfer(pc, 50) {
                    vulnerabilities.push(MultiTokenRewardVulnerability {
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: format!(
                            "Reward claim at PC {} doesn't verify token balance before transfer. \
                            With multiple reward tokens, insufficient balance in one can break entire claim.",
                            pc
                        ),
                        exploit_scenario:
                            "Multi-Token Claim DoS:\n\
                             1. Protocol has rewards in USDC, USDT, DAI\n\
                             2. USDC rewards run out\n\
                             3. User tries to claim all rewards\n\
                             4. Transaction reverts due to USDC insufficient balance\n\
                             5. User cannot claim USDT and DAI either\n\
                             6. Funds stuck until USDC is refilled\n\n\
                             Fix: Check balance and skip if insufficient:\n\
                             for (uint i = 0; i < rewardTokens.length; i++) {\n\
                                 uint256 pending = calculatePending(rewardTokens[i], user);\n\
                                 uint256 balance = rewardTokens[i].balanceOf(this);\n\
                                 if (balance >= pending && pending > 0) {\n\
                                     rewardTokens[i].transfer(user, pending);\n\
                                 }\n\
                             }".to_string(),
                        location: pc,
                    });
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_reward_reentrancy(&self) -> Vec<MultiTokenRewardVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            if self.is_transfer_call(pc) {
                if let Some(sstore_pc) = self.find_next_sstore(pc, 80) {
                    if self.has_multiple_external_calls_between(pc, sstore_pc) {
                        vulnerabilities.push(MultiTokenRewardVulnerability {
                            severity: SecuritySeverity::Critical,
                            confidence: 0.70,
                            description: format!(
                                "Reward distribution at PC {} updates state after multiple external calls. \
                                With ERC777 or hooks-enabled reward tokens, reentrancy can drain rewards.",
                                pc
                            ),
                            exploit_scenario:
                                "Multi-Token Reward Reentrancy:\n\
                                 1. Protocol distributes TOKEN_A (ERC777) and TOKEN_B\n\
                                 2. User calls claimRewards()\n\
                                 3. Protocol transfers TOKEN_A (ERC777 callback)\n\
                                 4. In callback, user re-enters claimRewards()\n\
                                 5. Reward index not yet updated\n\
                                 6. User claims TOKEN_A again\n\
                                 7. Protocol transfers TOKEN_B\n\
                                 8. User drains both reward pools\n\n\
                                 Fix: Update state before any transfers:\n\
                                 function claimRewards() nonReentrant {\n\
                                     for (uint i = 0; i < rewardTokens.length; i++) {\n\
                                         uint256 pending = calculatePending(rewardTokens[i]);\n\
                                         userRewardDebt[msg.sender][rewardTokens[i]] = pending;\n\
                                     }\n\
                                     for (uint i = 0; i < rewardTokens.length; i++) {\n\
                                         uint256 pending = userRewardDebt[msg.sender][rewardTokens[i]];\n\
                                         if (pending > 0) {\n\
                                             rewardTokens[i].transfer(msg.sender, pending);\n\
                                         }\n\
                                     }\n\
                                 }".to_string(),
                            location: pc,
                        });
                    }
                }
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn is_reward_calculation(&self, pc: usize) -> bool {
        if pc + 50 >= self.bytecode.len() { return false; }
        let mut has_mul = false;
        let mut has_div = false;
        for i in pc..(pc + 50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x02 { has_mul = true; }
            if self.bytecode[i] == 0x04 { has_div = true; }
        }
        has_mul && has_div
    }

    fn has_index_update_protection(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        let mut sstore_count = 0;
        for i in pc..end {
            if self.bytecode[i] == 0x55 { sstore_count += 1; }
        }
        sstore_count >= 2
    }

    fn is_transfer_call(&self, pc: usize) -> bool {
        if pc + 40 >= self.bytecode.len() { return false; }
        self.bytecode[pc..].windows(4).take(40).any(|w| w == [0xa9, 0x05, 0x9c, 0xbb])
    }

    fn has_multiple_reward_tokens(&self, pc: usize, range: usize) -> bool {
        let end = (pc + range).min(self.bytecode.len());
        let mut transfer_count = 0;
        for i in pc..end {
            if self.is_transfer_call(i) { transfer_count += 1; }
        }
        transfer_count >= 2
    }

    fn has_balance_check_before_transfer(&self, pc: usize, range: usize) -> bool {
        let start = pc.saturating_sub(range);
        for i in start..pc {
            if self.bytecode[i..].windows(4).take(10).any(|w| w == [0x70, 0xa0, 0x82, 0x31]) {
                return true;
            }
        }
        false
    }

    fn find_next_sstore(&self, start: usize, range: usize) -> Option<usize> {
        let end = (start + range).min(self.bytecode.len());
        for i in start..end {
            if self.bytecode[i] == 0x55 { return Some(i); }
        }
        None
    }

    fn has_multiple_external_calls_between(&self, start: usize, end: usize) -> bool {
        let end = end.min(self.bytecode.len());
        let mut call_count = 0;
        for i in start..end {
            if matches!(self.bytecode[i], 0xf1 | 0xf2 | 0xf4 | 0xfa) {
                call_count += 1;
            }
        }
        call_count >= 2
    }
}
