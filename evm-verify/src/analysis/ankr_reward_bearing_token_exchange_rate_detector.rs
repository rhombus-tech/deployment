use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnkrRewardBearingTokenVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct AnkrRewardBearingTokenExchangeRateDetector {
    bytecode: Vec<u8>,
}

impl AnkrRewardBearingTokenExchangeRateDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<AnkrRewardBearingTokenVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_exchange_rate_manipulation());
        vulnerabilities.extend(self.detect_reward_distribution_frontrun());
        vulnerabilities.extend(self.detect_burn_mint_ratio_exploit());

        vulnerabilities
    }

    fn detect_exchange_rate_manipulation(&self) -> Vec<AnkrRewardBearingTokenVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x04 { // DIV (ankrETH to ETH exchange rate)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_total_assets = window.iter().any(|&b| b == 0x54); // SLOAD (total staked ETH)
                let has_total_supply = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                
                if has_total_assets && has_total_supply {
                    let has_oracle_validation = window.iter().any(|&b| b == 0xFA); // STATICCALL (oracle)
                    let has_rate_bounds = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if !has_oracle_validation || !has_rate_bounds {
                        vulns.push(AnkrRewardBearingTokenVulnerability {
                            pc,
                            vulnerability_type: "ExchangeRateManipulation".to_string(),
                            description: format!(
                                "Ankr exchange rate calculation at PC {} uses unvalidated on-chain state. Rate = totalStakedETH / ankrETH.totalSupply(). Attack: \
                                flashloan ETH, stake large amount inflating totalStakedETH temporarily, exchange rate spikes, mint ankrETH at inflated rate, unstake, \
                                repay flashloan, profit from temporary rate manipulation. Or: exploit burn/mint to manipulate supply. Missing: oracle-based exchange \
                                rate verification, rate change limits per block, TWAP for rate calculation. Should use: external price oracle or time-weighted rate.",
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

    fn detect_reward_distribution_frontrun(&self) -> Vec<AnkrRewardBearingTokenVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (reward distribution)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_reward_amount = window.iter().any(|&b| b == 0x01); // ADD (rewards)
                let has_oracle_report = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_reward_amount && has_oracle_report {
                    let has_snapshot_protection = window.iter().any(|&b| b == 0x43); // NUMBER (block snapshot)
                    let has_delay = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    
                    if !has_snapshot_protection {
                        vulns.push(AnkrRewardBearingTokenVulnerability {
                            pc,
                            vulnerability_type: "RewardDistributionFrontrun".to_string(),
                            description: format!(
                                "Reward distribution at PC {} allows frontrunning. Ankr distributes staking rewards by increasing exchange rate. Attack: observe \
                                reward distribution tx in mempool, frontrun with large ankrETH purchase, rewards distributed immediately increasing exchange rate, \
                                sell ankrETH at higher rate. Instant profit from rewards meant for long-term stakers. Missing: reward distribution snapshot (balances \
                                at block N-1), gradual reward distribution, deposit lockup for reward eligibility. Should snapshot balances before reward distribution \
                                or linearly vest rewards.",
                                pc
                            ),
                            confidence: 0.86,
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

    fn detect_burn_mint_ratio_exploit(&self) -> Vec<AnkrRewardBearingTokenVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x02 { // MUL (burn/mint amount calculation)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_exchange_rate = window.iter().any(|&b| b == 0x04); // DIV (rate calc)
                let has_burn_or_mint = window.iter().any(|&b| b == 0x55); // SSTORE (supply change)
                
                if has_exchange_rate && has_burn_or_mint {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_rounding_protection = window.iter().any(|&b| b == 0x01); // ADD (rounding up)
                    let has_minimum_amount = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if !has_rounding_protection {
                        vulns.push(AnkrRewardBearingTokenVulnerability {
                            pc,
                            vulnerability_type: "BurnMintRatioExploit".to_string(),
                            description: format!(
                                "Burn/mint calculation at PC {} vulnerable to rounding manipulation. When unstaking: ethAmount = ankrETH * exchangeRate. Attack: \
                                deposit 1 wei ankrETH when rate = 1.05, should get 1.05 wei ETH but rounds to 1 wei, 0.05 wei lost. Repeat millions of times in \
                                loop, accumulate rounding dust. Or: manipulate rate to create favorable rounding for attacker, unfavorable for protocol. Missing: \
                                minimum stake/unstake amount, rounding in user's favor, dust accumulation prevention. Should enforce: minAmount >= 0.01 ETH or \
                                round up on withdrawals.",
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
