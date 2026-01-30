use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FutarchyVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct FutarchyGovernanceAttackDetector {
    bytecode: Vec<u8>,
}

impl FutarchyGovernanceAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<FutarchyVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_decision_market_manipulation());
        vulnerabilities.extend(self.detect_conditional_token_arbitrage());
        vulnerabilities.extend(self.detect_metric_manipulation());

        vulnerabilities
    }

    fn detect_decision_market_manipulation(&self) -> Vec<FutarchyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (governance decision)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_market_price = window.iter().any(|&b| b == 0x04); // DIV (price from AMM)
                let has_decision_logic = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 1;
                
                if has_market_price && has_decision_logic {
                    let has_liquidity_check = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 3;
                    let has_manipulation_detection = window.iter().filter(|&&b| b == 0x42).count() >= 2; // Time-based checks
                    
                    if !has_liquidity_check && !has_manipulation_detection {
                        vulns.push(FutarchyVulnerability {
                            pc,
                            vulnerability_type: "DecisionMarketManipulation".to_string(),
                            description: format!(
                                "Futarchy decision mechanism at PC {} vulnerable to market manipulation. Attack: governance uses prediction market prices to make decisions \
                                (e.g., if market price of 'token value if we do X' > 'token value if we don't do X', do X), attacker manipulates low-liquidity decision \
                                market by buying 'do X' tokens, decision executes based on manipulated price, attacker profits from actual decision outcome. Cost of \
                                manipulation < benefit. Missing: minimum liquidity requirements for decision validity, TWAP instead of spot price, manipulation detection \
                                (sudden large trades), skin-in-game requirements. Should require: decision markets have $1M+ liquidity and use 24h TWAP for decision.",
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

    fn detect_conditional_token_arbitrage(&self) -> Vec<FutarchyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (conditional token redemption)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_conditional_logic = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                let has_token_split = window.iter().any(|&b| b == 0x04); // DIV
                
                if has_conditional_logic {
                    let has_arbitrage_prevention = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    let has_atomic_settlement = window.iter().filter(|&&b| b == 0xF1).count() == 1;
                    
                    if !has_arbitrage_prevention {
                        vulns.push(FutarchyVulnerability {
                            pc,
                            vulnerability_type: "ConditionalTokenArbitrage".to_string(),
                            description: format!(
                                "Conditional token mechanism at PC {} allows risk-free arbitrage. Attack: futarchy creates conditional tokens (token_if_yes, token_if_no), \
                                prices should sum to 1 (100% probability), if token_yes + token_no != 1, arbitrage exists. Buy underpriced pair, wait for resolution, \
                                redeem for guaranteed profit. Example: token_yes = $0.45, token_no = $0.50, buy both for $0.95, resolution occurs, redeem for $1.00, \
                                profit $0.05 risk-free. Missing: atomic price synchronization between conditional markets, instant arbitrage correction mechanism, \
                                redemption windows. Should enforce: token_yes + token_no = constant 1.00 via bonding curve or arbitrage bots.",
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

    fn detect_metric_manipulation(&self) -> Vec<FutarchyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xFA { // STATICCALL (metric oracle)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_success_metric = window.iter().any(|&b| b == 0x02); // MUL (metric usage)
                let has_decision_based_on_metric = window.iter().any(|&b| b == 0x55); // SSTORE
                
                if has_success_metric && has_decision_based_on_metric {
                    let has_goodhart_protection = window.iter().filter(|&&b| b == 0xFA).count() >= 3; // Multiple metrics
                    let has_manipulation_resistance = window.iter().any(|&b| b == 0x42); // Time-averaging
                    
                    if !has_goodhart_protection {
                        vulns.push(FutarchyVulnerability {
                            pc,
                            vulnerability_type: "MetricManipulation".to_string(),
                            description: format!(
                                "Futarchy success metric at PC {} vulnerable to Goodhart's Law exploitation. Attack: governance optimizes for single metric (e.g., token \
                                price, TVL, daily active users), attacker manipulates metric without creating real value. Example: decision market uses 'TVL in 30 days' \
                                as success metric, attacker proposes change, deposits large funds temporarily to inflate TVL, decision executes, attacker withdraws. Metric \
                                gamed but protocol not actually improved. Goodhart's Law: 'when a measure becomes a target, it ceases to be a good measure'. Missing: \
                                composite metrics (multiple weighted factors), manipulation-resistant metrics, long-term averaging. Should use: basket of uncorrelated \
                                metrics or fundamental value measures resistant to short-term gaming.",
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
}
