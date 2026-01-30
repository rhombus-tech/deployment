use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YearnV3StrategyVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct YearnV3StrategyLossSocializationDetector {
    bytecode: Vec<u8>,
}

impl YearnV3StrategyLossSocializationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<YearnV3StrategyVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_strategy_loss_unfair_distribution());
        vulnerabilities.extend(self.detect_profit_fee_asymmetry());
        vulnerabilities.extend(self.detect_share_price_manipulation_on_loss());

        vulnerabilities
    }

    fn detect_strategy_loss_unfair_distribution(&self) -> Vec<YearnV3StrategyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x04 { // DIV (share price calculation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_total_assets = window.iter().any(|&b| b == 0x54); // SLOAD
                let has_total_supply = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                
                if has_total_assets && has_total_supply {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_loss_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_timestamp_gate = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    if !has_timestamp_gate {
                        vulns.push(YearnV3StrategyVulnerability {
                            pc,
                            vulnerability_type: "StrategyLossUnfairDistribution".to_string(),
                            description: format!(
                                "Yearn V3 share price calculation at PC {} socializes strategy losses immediately. Attack: strategy reports loss, pricePerShare \
                                drops instantly, attacker who deposited 1 block ago bears full loss despite new depositor. Unfair: early depositors withdraw before \
                                loss reported, late depositors absorb disproportionate loss. Missing: loss waterfall (FIFO/LIFO), time-weighted loss distribution, \
                                strategy loss quarantine period. Should delay loss socialization or distribute based on deposit timing.",
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

    fn detect_profit_fee_asymmetry(&self) -> Vec<YearnV3StrategyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x02 { // MUL (fee calculation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_profit = window.iter().any(|&b| b == 0x03); // SUB (gain calculation)
                let has_performance_fee = window.iter().filter(|&&b| b == 0x02).count() >= 2;
                
                if has_profit {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_loss_rebate = window.iter().any(|&b| b == 0x01); // ADD (loss compensation)
                    
                    if !has_loss_rebate {
                        vulns.push(YearnV3StrategyVulnerability {
                            pc,
                            vulnerability_type: "ProfitFeeAsymmetry".to_string(),
                            description: format!(
                                "Performance fee at PC {} charges on profits but no rebate on losses. Yearn takes 10-20% performance fee on gains. Attack/Issue: \
                                vault alternates profit/loss, protocol takes fee on every profit, depositors absorb 100% of losses, asymmetric fee structure favors \
                                protocol over depositors during volatility. Missing: high watermark (only fee on net new highs), loss carryforward, fee rebate mechanism. \
                                Should track: fee only on (currentValue > previousHigh).",
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

    fn detect_share_price_manipulation_on_loss(&self) -> Vec<YearnV3StrategyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (strategy debt update)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_report_loss = window.iter().any(|&b| b == 0x03); // SUB (loss)
                let has_debt_update = window.iter().filter(|&&b| b == 0x55).count() >= 2;
                
                if has_report_loss {
                    let has_oracle_validation = window.iter().any(|&b| b == 0xFA); // STATICCALL (price check)
                    let has_loss_cap = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if !has_oracle_validation && !has_loss_cap {
                        vulns.push(YearnV3StrategyVulnerability {
                            pc,
                            vulnerability_type: "SharePriceManipulationOnLoss".to_string(),
                            description: format!(
                                "Strategy loss reporting at PC {} without validation. Attack: malicious strategy reports fake massive loss, share price crashes, \
                                attacker mints shares at depressed price (deposit when pricePerShare artificially low), strategy 'recovers' loss, attacker redeems \
                                at normal price. Or: strategist colludes with whale to buy discounted shares. Missing: oracle-verified loss validation, maximum loss \
                                per report, strategy loss auditing. Should require: external price verification for large losses.",
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
}
