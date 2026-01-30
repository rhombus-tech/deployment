use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearpoolBorrowerCreditScoreGamingVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ClearpoolBorrowerCreditScoreGamingDetector {
    bytecode: Vec<u8>,
}

impl ClearpoolBorrowerCreditScoreGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ClearpoolBorrowerCreditScoreGamingVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_score_inflation_via_small_loans());
        vulnerabilities.extend(self.detect_temporal_gaming());
        vulnerabilities.extend(self.detect_cross_pool_manipulation());
        vulnerabilities
    }

    fn detect_score_inflation_via_small_loans(&self) -> Vec<ClearpoolBorrowerCreditScoreGamingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (credit score update)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let updates_score = self.bytecode[start..pc].iter().filter(|&&b| b == 0x01).count() >= 1;
                if updates_score {
                    let has_amount_weighting = self.bytecode[start..pc].iter().filter(|&&b| b == 0x02).count() >= 1;
                    if !has_amount_weighting {
                        vulns.push(ClearpoolBorrowerCreditScoreGamingVulnerability {
                            pc,
                            vulnerability_type: "ScoreInflationViaSmallLoans".to_string(),
                            description: format!("Credit score update at PC {} doesn't weight by loan amount, enabling score inflation. Attack: borrower takes many tiny loans and repays perfectly to build high credit score, then takes maximum loan and defaults, lenders lose despite high score. Real attack: Clearpool borrower takes 100 loans of $1,000 each over 6 months, repays all on time, credit score reaches 950/1000, credit line increases to $5M based on perfect history, borrower draws full $5M and defaults, lenders lose despite borrower's 'excellent' track record. Example: borrower strategy = borrow minimum amounts repeatedly where repayment guaranteed by low risk, build reputation through volume not value, exploit reputation for large unsecured loan, actual creditworthiness never tested. Missing: loan amount weighting in score calculation, risk-adjusted performance. Should implement: credit_score = f(repayment_rate * sqrt(total_amount_borrowed)). Fix: weight credit score by loan size using log scale, require minimum loan amounts for score increases (prevent penny-loan farming), implement stress test before credit line expansion (simulate default scenario), cap credit score increases from loans <$10k at 10% of total score, add diminishing returns for repeated small loans.", pc),
                            confidence: 0.87,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_temporal_gaming(&self) -> Vec<ClearpoolBorrowerCreditScoreGamingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x42 { // TIMESTAMP (repayment timing)
                let window_end = (pc + 100).min(self.bytecode.len());
                let affects_score = self.bytecode[pc..window_end].iter().any(|&b| b == 0x55);
                if affects_score {
                    let has_late_penalty = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x10).count() >= 2;
                    if !has_late_penalty {
                        vulns.push(ClearpoolBorrowerCreditScoreGamingVulnerability {
                            pc,
                            vulnerability_type: "TemporalGaming".to_string(),
                            description: format!("Repayment timing at PC {} doesn't penalize strategic late payments enabling temporal gaming. Attack: borrower strategically times repayments to maximize credit score while minimizing actual capital efficiency, repays seconds before deadline repeatedly, technically 'on-time' but demonstrates poor cashflow management. Real vulnerability: Clearpool considers repayment 'on-time' if within grace period, borrower always repays at block.timestamp == deadline - 1 second, builds perfect payment history, actually indicates cashflow stress and high default risk. Example: borrower has $1M loan due every 30 days, repays at day 29.99 every cycle for 12 months, credit score increases to maximum, no penalty for cutting it close, financial stress indicators ignored, borrower eventually misses deadline by 2 seconds and can't recover. Missing: early payment bonuses, late payment severity tracking, repayment pattern analysis. Should implement: penalize consistent deadline-cutting, reward early payments. Fix: implement payment timing score = (avg_days_early / loan_term) * 100, reduce credit score for repayments in final 10% of grace period, bonus points for repayments >7 days early, analyze repayment variance (high variance = stress indicator), require cashflow stability metrics before credit increases.", pc),
                            confidence: 0.81,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_cross_pool_manipulation(&self) -> Vec<ClearpoolBorrowerCreditScoreGamingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x54 { // SLOAD (borrower score lookup)
                let window_end = (pc + 100).min(self.bytecode.len());
                let single_pool_score = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x54).count() == 1;
                if single_pool_score {
                    let approves_loan = self.bytecode[pc..window_end].iter().any(|&b| b == 0x55);
                    if approves_loan {
                        vulns.push(ClearpoolBorrowerCreditScoreGamingVulnerability {
                            pc,
                            vulnerability_type: "CrossPoolManipulation".to_string(),
                            description: format!("Credit score lookup at PC {} uses single-pool score without cross-pool verification. Attack: borrower builds excellent credit score in pool A with small loans, simultaneously has poor history in pools B and C, pool A only sees own data, approves large loan, borrower defaults. Real attack: Clearpool borrower maintains 100% repayment rate in USDC pool, simultaneously defaults on 3 loans in ETH pool, USDC pool credit score 950, ETH pool score 200, pools don't share data, borrower gets approved for $10M USDC loan based on siloed perfect history, defaults immediately. Example: borrower exploits lack of cross-pool oracle, builds reputation in low-liquidity pool with wash loans, leverages that score to borrow from high-liquidity pool, effectively Sybil attacking the reputation system via pool segmentation. Missing: cross-pool credit aggregation, global borrower reputation oracle. Should implement: query borrower performance across all Clearpool instances. Fix: implement global borrower credit registry accessible by all pools, require weighted average score across pools (weighted by TVL), flag borrowers with >50% score variance between pools, mandate cross-pool query before loans >$100k, slash borrower across all pools for any default, implement reputation portability with fraud detection.", pc),
                            confidence: 0.83,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
