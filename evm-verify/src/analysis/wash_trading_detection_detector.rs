use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WashTradingVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct WashTradingDetectionDetector {
    bytecode: Vec<u8>,
}

impl WashTradingDetectionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<WashTradingVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_self_trading_vulnerability());
        vulnerabilities.extend(self.detect_circular_trading_pattern());
        vulnerabilities.extend(self.detect_volume_inflation());

        vulnerabilities
    }

    fn detect_self_trading_vulnerability(&self) -> Vec<WashTradingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (swap/trade execution)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_trade_logic = window.iter().any(|&b| b == 0x02); // MUL (amount calculation)
                let has_sender_check = window.iter().any(|&b| b == 0x33); // CALLER
                
                if has_trade_logic {
                    let has_self_trade_prevention = window.iter().filter(|&&b| b == 0x14).count() >= 2; // Multiple EQ checks
                    let has_recipient_validation = window.iter().filter(|&&b| b == 0x33).count() >= 2;
                    
                    if !has_self_trade_prevention {
                        vulns.push(WashTradingVulnerability {
                            pc,
                            vulnerability_type: "SelfTradingVulnerability".to_string(),
                            description: format!(
                                "Trade execution at PC {} allows self-trading (wash trading). Attack: user creates two accounts, trades asset back and forth between them \
                                at inflated prices to: (1) fake volume metrics for token listing, (2) manipulate TWAP oracle by creating artificial trades, (3) trigger \
                                volume-based rewards or airdrops, (4) create false market depth impression. Missing: sender != recipient validation, trade pattern analysis, \
                                minimum hold time between trades, address clustering detection. Should enforce: buyer != seller, track trading patterns across related addresses.",
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

    fn detect_circular_trading_pattern(&self) -> Vec<WashTradingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (position tracking)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_multiple_swaps = window.iter().filter(|&&b| b == 0xF1).count() >= 2; // Multiple CALLs
                let has_balance_tracking = window.iter().filter(|&&b| b == 0x54).count() >= 3;
                
                if has_multiple_swaps {
                    let has_cycle_detection = window.iter().filter(|&&b| b == 0x20).count() >= 2; // KECCAK256 (path hashing)
                    
                    if !has_cycle_detection {
                        vulns.push(WashTradingVulnerability {
                            pc,
                            vulnerability_type: "CircularTradingPattern".to_string(),
                            description: format!(
                                "Multi-hop swap at PC {} vulnerable to circular wash trading. Attack: execute circular trades A→B→C→A at manipulated prices to inflate \
                                volume without net position change. Example: buy token A with B at high price, swap A for C, swap C back to B, repeat. Creates illusion \
                                of high trading activity and liquidity. Used to: game volume-based protocol incentives, manipulate price oracles using trade-weighted \
                                metrics, satisfy listing requirements. Missing: cycle detection in swap paths, net position change validation, cooldown between reverse \
                                trades. Should track: complete trading paths and prevent zero-sum circular routes.",
                                pc
                            ),
                            confidence: 0.82,
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

    fn detect_volume_inflation(&self) -> Vec<WashTradingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x02 { // MUL (volume calculation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_volume_tracking = window.iter().any(|&b| b == 0x01); // ADD (cumulative volume)
                let has_reward_based_on_volume = window.iter().filter(|&&b| b == 0x04).count() >= 2;
                
                if has_volume_tracking && has_reward_based_on_volume {
                    let has_unique_user_tracking = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    let has_sybil_resistance = window.iter().any(|&b| b == 0xFA); // STATICCALL (proof verification)
                    
                    if !has_unique_user_tracking && !has_sybil_resistance {
                        vulns.push(WashTradingVulnerability {
                            pc,
                            vulnerability_type: "VolumeInflation".to_string(),
                            description: format!(
                                "Volume-based rewards at PC {} vulnerable to wash trading inflation. Attack: protocol distributes rewards proportional to trading volume, \
                                attacker creates Sybil accounts, wash trades between them to inflate volume count, earns disproportionate rewards. Cost: only trading fees. \
                                Profit: volume rewards - fees. Real-world: many DEX liquidity mining programs exploited this way. Missing: unique user verification, \
                                net volume vs gross volume tracking, trading pattern analysis, proof of unique humanity. Should use: user caps, quadratic distribution, \
                                or stake-weighted volume metrics.",
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
}
