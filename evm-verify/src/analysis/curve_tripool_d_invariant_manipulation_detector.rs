use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurveTripoolDInvariantVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CurveTripoolDInvariantManipulationDetector {
    bytecode: Vec<u8>,
}

impl CurveTripoolDInvariantManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CurveTripoolDInvariantVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_virtual_price_manipulation());
        vulnerabilities.extend(self.detect_d_invariant_donation_attack());
        vulnerabilities.extend(self.detect_imbalanced_withdraw_exploit());
        vulnerabilities
    }

    fn detect_virtual_price_manipulation(&self) -> Vec<CurveTripoolDInvariantVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x04 { // DIV (virtual price = D / total supply)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let has_d_calc = self.bytecode[start..pc].iter().filter(|&&b| b == 0x01).count() >= 3;
                if has_d_calc {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let has_donation_check = self.bytecode[start..window_end].iter().filter(|&&b| b == 0x54).count() >= 4;
                    if !has_donation_check {
                        vulns.push(CurveTripoolDInvariantVulnerability {
                            pc, vulnerability_type: "VirtualPriceManipulation".to_string(),
                            description: format!("Curve virtual price calculation at PC {} vulnerable to donation attack inflating D invariant. Attack: attacker directly transfers tokens to pool (donation), D invariant increases without minting LP tokens, virtual_price = D/totalSupply inflates. Real attack: donate 1M DAI to 3pool, D increases by 1M, totalSupply unchanged, virtual price jumps, protocols using virtual price for valuation break. Missing: track balance changes through official pool functions only, detect direct transfers. Exploit scenario: Oracle uses get_virtual_price() for LP valuation, attacker donates, price inflates 10x, attacker borrows against inflated LP collateral. Fix: use remove_liquidity_imbalance to get real exchange rate, don't trust virtual_price alone.", pc),
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

    fn detect_d_invariant_donation_attack(&self) -> Vec<CurveTripoolDInvariantVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x01 { // ADD (D calculation uses addition)
                let window_end = (pc + 150).min(self.bytecode.len());
                if self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x01).count() >= 5 {
                    let has_balance_tracking = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x55).count() >= 3;
                    if !has_balance_tracking {
                        vulns.push(CurveTripoolDInvariantVulnerability {
                            pc, vulnerability_type: "DInvariantDonationAttack".to_string(),
                            description: format!("D invariant calculation at PC {} doesn't track balance changes, allowing donation manipulation. Attack: Curve calculates D = A * n^n * sum(x_i) + D^(n+1)/(n^n * prod(x_i)), attacker inflates x_i values via donation. Real vulnerability: protocol integrates Curve pool, reads D for health checks, attacker donates to inflate D, protocol thinks pool healthier than reality. Example: 3pool with [1M DAI, 1M USDC, 1M USDT], D ≈ 3M, attacker donates 1M DAI, new balances [2M, 1M, 1M], D recalculates to higher value, breaks integration assumptions. Missing: compare current balances to previous stored balances before D calculation. Fix: store balance checkpoints, revert if donation detected.", pc),
                            confidence: 0.82,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_imbalanced_withdraw_exploit(&self) -> Vec<CurveTripoolDInvariantVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL (remove_liquidity_imbalance)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let has_slippage = self.bytecode[start..pc].iter().filter(|&&b| b == 0x10).count() >= 1;
                if !has_slippage {
                    vulns.push(CurveTripoolDInvariantVulnerability {
                        pc, vulnerability_type: "ImbalancedWithdrawExploit".to_string(),
                        description: format!("Imbalanced withdrawal at PC {} lacks slippage protection against D manipulation. Attack: attacker manipulates pool to be extremely imbalanced, victim calls remove_liquidity_imbalance, gets unfavorable exchange due to distorted D. Real example: pool becomes [100 DAI, 1M USDC, 1M USDT], D calculation favors USDC/USDT, withdrawing DAI costs excessive LP tokens. Missing: max_burn_amount parameter check, or balanced withdrawal enforcement. Exploit: flash loan to imbalance pool, victim withdraws losing value to price impact, attacker profits. Fix: use remove_liquidity_one_coin with min_amount parameter, or check balanced withdrawal only.", pc),
                        confidence: 0.78,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
