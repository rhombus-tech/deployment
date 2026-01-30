use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictionMarketVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct PredictionMarketOracleManipulationDetector {
    bytecode: Vec<u8>,
}

impl PredictionMarketOracleManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<PredictionMarketVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_single_oracle_dependency());
        vulnerabilities.extend(self.detect_oracle_resolution_frontrun());
        vulnerabilities.extend(self.detect_market_resolution_timing_attack());

        vulnerabilities
    }

    fn detect_single_oracle_dependency(&self) -> Vec<PredictionMarketVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (market resolution)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_oracle_call = window.iter().any(|&b| b == 0xFA); // STATICCALL
                let has_outcome_determination = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 1;
                
                if has_oracle_call && has_outcome_determination {
                    let has_multiple_oracles = window.iter().filter(|&&b| b == 0xFA).count() >= 3;
                    let has_dispute_mechanism = window.iter().any(|&b| b == 0x42); // TIMESTAMP (dispute period)
                    
                    if !has_multiple_oracles && !has_dispute_mechanism {
                        vulns.push(PredictionMarketVulnerability {
                            pc,
                            vulnerability_type: "SingleOracleDependency".to_string(),
                            description: format!(
                                "Prediction market resolution at PC {} relies on single oracle. Attack: market outcome worth millions, single oracle controls resolution, \
                                oracle operator manipulates result for profit or is bribed. Example: sports betting market on game outcome, oracle reports wrong winner, \
                                profits from own bets. Single point of failure and corruption. Missing: multi-oracle consensus (require 3/5 agreement), dispute resolution \
                                period allowing challenges, economic stake from oracle (bond that's slashed for wrong reports). Should use: decentralized oracle network \
                                like UMA's optimistic oracle or Chainlink with multiple independent data sources.",
                                pc
                            ),
                            confidence: 0.88,
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

    fn detect_oracle_resolution_frontrun(&self) -> Vec<PredictionMarketVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xFA { // STATICCALL (oracle query)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_market_settlement = window.iter().any(|&b| b == 0x55); // SSTORE
                let has_payout_calculation = window.iter().any(|&b| b == 0x02); // MUL
                
                if has_market_settlement {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_commit_reveal = pre_window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    let has_delayed_settlement = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    
                    if !has_commit_reveal && !has_delayed_settlement {
                        vulns.push(PredictionMarketVulnerability {
                            pc,
                            vulnerability_type: "OracleResolutionFrontrun".to_string(),
                            description: format!(
                                "Market resolution at PC {} vulnerable to oracle frontrunning. Attack: oracle sees off-chain event outcome (e.g., election result) before \
                                submitting on-chain, oracle or colluding trader places large bet on winning outcome, then oracle submits resolution immediately, profits \
                                from insider knowledge of resolution data. Time gap between knowing outcome and resolution allows exploitation. Missing: commit-reveal for \
                                oracle submissions, time delay between resolution submission and market settlement, sealed oracle data until settlement block. Should \
                                implement: oracle commits hash(outcome + salt), market continues trading briefly, oracle reveals, settlement occurs after reveal delay.",
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

    fn detect_market_resolution_timing_attack(&self) -> Vec<PredictionMarketVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP (resolution timing)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_settlement_trigger = window.iter().any(|&b| b == 0x55); // SSTORE
                let has_early_resolution = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 1;
                
                if has_settlement_trigger && has_early_resolution {
                    let has_minimum_delay = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    let has_participation_threshold = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 3;
                    
                    if !has_minimum_delay {
                        vulns.push(PredictionMarketVulnerability {
                            pc,
                            vulnerability_type: "MarketResolutionTimingAttack".to_string(),
                            description: format!(
                                "Market resolution timing at PC {} allows manipulation. Attack: market allows resolution immediately after event, attacker with information \
                                advantage triggers resolution before others can react. Example: binary market on 'will ETH hit $3000 today', ETH briefly touches $3000, \
                                insider immediately calls resolve() while price still at $3000, locks in 'yes' outcome, price drops back, market participants didn't have \
                                time to adjust positions. Missing: minimum resolution delay after event, grace period for final trades, snapshot time clearly defined. \
                                Should require: resolution only callable after event + N minutes, allowing all participants to react to public information.",
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
