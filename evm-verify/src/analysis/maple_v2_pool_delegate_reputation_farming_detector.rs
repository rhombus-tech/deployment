use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapleV2PoolDelegateReputationFarmingVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct MapleV2PoolDelegateReputationFarmingDetector {
    bytecode: Vec<u8>,
}

impl MapleV2PoolDelegateReputationFarmingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<MapleV2PoolDelegateReputationFarmingVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_wash_lending());
        vulnerabilities.extend(self.detect_short_term_reputation_gaming());
        vulnerabilities.extend(self.detect_circular_loan_networks());
        vulnerabilities
    }

    fn detect_wash_lending(&self) -> Vec<MapleV2PoolDelegateReputationFarmingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (loan issuance)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let issues_loan = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 2;
                if issues_loan {
                    let checks_borrower_history = self.bytecode[start..pc].iter().filter(|&&b| b == 0x54).count() >= 3;
                    if !checks_borrower_history {
                        vulns.push(MapleV2PoolDelegateReputationFarmingVulnerability {
                            pc,
                            vulnerability_type: "WashLending".to_string(),
                            description: format!("Loan issuance at PC {} doesn't verify borrower independence, enabling wash lending. Attack: pool delegate creates shell borrower entities, issues loans to own entities, entities repay on time using delegate funds, builds perfect repayment track record, attracts real lenders, then defaults on real loans. Real attack: Maple v2 delegate controls borrower wallets, issues 50 small loans to shells, all repay perfectly over 12 months, delegate reputation score 100%, real lenders deposit $20M based on track record, delegate issues $15M to real risky borrower who defaults. Example: delegate address 0xAAA, borrower addresses 0xBBB-0xFFF all funded from 0xAAA, loans issued and repaid in circular pattern, on-chain appears as 200 successful loans, actually wash trading, reputation score inflated 10x. Missing: borrower independence verification, fund flow analysis, Sybil detection. Should implement: verify borrower addresses not funded by delegate. Fix: require borrower addresses exist >90 days before loan, check no shared funding sources via graph analysis, implement reputation decay for clustered addresses, require external credit oracle validation, slash delegate stake for Sybil borrowers, cap loans to new addresses at 5% pool size.", pc),
                            confidence: 0.86,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_short_term_reputation_gaming(&self) -> Vec<MapleV2PoolDelegateReputationFarmingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x54 { // SLOAD (reputation check)
                let window_end = (pc + 100).min(self.bytecode.len());
                let uses_reputation = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x14).count() >= 1;
                if uses_reputation {
                    let has_time_weighting = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x42).count() >= 2;
                    if !has_time_weighting {
                        vulns.push(MapleV2PoolDelegateReputationFarmingVulnerability {
                            pc,
                            vulnerability_type: "ShortTermReputationGaming".to_string(),
                            description: format!("Reputation calculation at PC {} lacks time-weighting, enabling short-term gaming. Attack: new pool delegate issues many tiny loans that repay quickly, rapidly accumulates reputation score without long-term track record, attracts large deposits, then defaults on large loan. Real vulnerability: Maple reputation based on repayment count not weighted by time/amount, delegate issues 100 loans of $1k each with 7-day terms, all repay (low risk), delegate reputation = 100% over 2 months, attracts $10M deposit, issues single $8M loan that defaults. Example: delegate A with 2-year track record and $50M managed gets same reputation score as delegate B with 1-month track record and $100k managed if both have 100% repayment rate, B is untested but appears equivalent. Missing: time-in-business weighting, amount-under-management scaling, stress-test history. Should implement: reputation = f(repayment_rate, time_active, amount_managed, market_conditions). Fix: multiply reputation score by sqrt(months_active), weight by total_value_managed, reduce score during market stress if delegate doesn't adapt, require minimum 12-month track record for large pools, implement non-linear reputation growth (diminishing returns for short-term success).", pc),
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

    fn detect_circular_loan_networks(&self) -> Vec<MapleV2PoolDelegateReputationFarmingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x35 { // CALLDATALOAD (borrower address)
                let window_end = (pc + 120).min(self.bytecode.len());
                let creates_loan = self.bytecode[pc..window_end].iter().any(|&b| b == 0x55);
                if creates_loan {
                    let checks_circular_lending = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x54).count() >= 5;
                    if !checks_circular_lending {
                        vulns.push(MapleV2PoolDelegateReputationFarmingVulnerability {
                            pc,
                            vulnerability_type: "CircularLoanNetworks".to_string(),
                            description: format!("Loan creation at PC {} doesn't detect circular lending networks enabling reputation inflation. Attack: multiple Maple delegates collude, create circular lending arrangement, delegate A lends to B's borrower who repays with loan from delegate C's pool to delegate B's borrower, creates appearance of liquidity and repayment while just circulating same capital. Real attack: 5 Maple delegates coordinate, pool A lends $10M to borrower X, borrower X immediately borrows $10M from pool B to repay pool A, borrower Y borrows from pool C to repay pool B, circular chain continues, all pools show perfect repayment, actually zero net lending occurred. Example: delegate network issues $100M in loans but only $20M real capital exists, remaining $80M circulates between colluding pools, all delegates build reputation from circular repayments, finally one delegate exits with real capital, cascade of defaults. Missing: cross-pool loan tracking, borrower capital source verification, network analysis. Should implement: detect when loan repayment funded by new loan. Fix: track borrower capital sources via graph analysis, flag if repayment comes from address that recently received loan, require borrowers prove revenue source for repayments, implement cross-pool coordination oracle, slash reputation for participating in circular networks, require minimum time between borrow and repay (prevent instant recycling).", pc),
                            confidence: 0.79,
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
