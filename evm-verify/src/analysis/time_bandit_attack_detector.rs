use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeBanditVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TimeBanditAttackDetector {
    bytecode: Vec<u8>,
}

impl TimeBanditAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<TimeBanditVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_profitable_reorg_incentive());
        vulnerabilities.extend(self.detect_liquidation_time_bandit());
        vulnerabilities.extend(self.detect_nft_auction_reorg());

        vulnerabilities
    }

    fn detect_profitable_reorg_incentive(&self) -> Vec<TimeBanditVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (large value transfer)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_large_value = window.windows(2).any(|w| {
                    w[0] == 0x6B || w[0] == 0x6C // PUSH12/PUSH13 (large amounts)
                });
                
                if has_large_value {
                    let has_finality_check = window.iter().any(|&b| b == 0x43); // NUMBER (confirmations)
                    let has_reorg_protection = window.iter().filter(|&&b| b == 0x40).count() >= 2; // BLOCKHASH checks
                    
                    if !has_reorg_protection {
                        vulns.push(TimeBanditVulnerability {
                            pc,
                            vulnerability_type: "ProfitableReorgIncentive".to_string(),
                            description: format!(
                                "Large value transfer at PC {} without reorg protection. Time bandit attack: when transaction value > block reward + fees, validator \
                                economically incentivized to reorganize chain. Example: $10M NFT sale in block N, current block reward = 2 ETH ($4K), attacker who lost \
                                auction creates 1-block reorg, replaces their losing bid with winning bid, profit = $10M - mining cost. Missing: multi-block confirmation \
                                requirement, reorg-resistant finality mechanism, value caps per block. Should require: significant confirmation depth or use finality \
                                gadget for high-value transfers.",
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

    fn detect_liquidation_time_bandit(&self) -> Vec<TimeBanditVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (liquidation state)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_liquidation_logic = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2; // LT, GT (health factor)
                let has_price_check = window.iter().any(|&b| b == 0xFA); // STATICCALL (oracle)
                
                if has_liquidation_logic && has_price_check {
                    let has_blockhash_verification = window.iter().filter(|&&b| b == 0x40).count() >= 2;
                    
                    if !has_blockhash_verification {
                        vulns.push(TimeBanditVulnerability {
                            pc,
                            vulnerability_type: "LiquidationTimeBandit".to_string(),
                            description: format!(
                                "Liquidation at PC {} vulnerable to time bandit. Attack: lending protocol uses oracle price at block N for liquidation, price temporarily \
                                drops making position liquidatable, liquidator profits $1M in single tx, validator sees profitable opportunity: reorg last few blocks, \
                                insert own liquidation tx instead, steal liquidation profit. Cost of reorg < liquidation profit. Missing: multi-block oracle price, \
                                confirmation depth for liquidations, MEV auction with redistribution. Should use: time-weighted oracle prices across multiple blocks or \
                                require liquidation only after price sustained for N blocks.",
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

    fn detect_nft_auction_reorg(&self) -> Vec<TimeBanditVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (auction winner)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_auction_end = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                let has_highest_bid = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 1;
                
                if has_auction_end && has_highest_bid {
                    let has_commit_reveal = window.iter().filter(|&&b| b == 0x20).count() >= 2; // KECCAK256 (commitments)
                    let has_extended_finalization = window.iter().filter(|&&b| b == 0x42).count() >= 3;
                    
                    if !has_commit_reveal && !has_extended_finalization {
                        vulns.push(TimeBanditVulnerability {
                            pc,
                            vulnerability_type: "NftAuctionReorg".to_string(),
                            description: format!(
                                "NFT auction finalization at PC {} susceptible to time bandit reorg. Attack: high-value NFT auction ends at block N with winning bid \
                                $5M, loser initiates reorg of blocks N-2 to N, replaces blocks with own version where they bid slightly higher earlier, wins auction. \
                                Auction allows late bidding without commit-reveal. Time bandit profitability: value of winning - reorg cost. Missing: commit-reveal \
                                scheme, extended auction period after last bid, finality confirmation period. Should implement: sealed bids with reveal phase or \
                                require bids committed 10+ blocks before auction end.",
                                pc
                            ),
                            confidence: 0.83,
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
