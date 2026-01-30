use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancerWeightedPoolSpotPriceVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct BalancerWeightedPoolSpotPriceDetector {
    bytecode: Vec<u8>,
}

impl BalancerWeightedPoolSpotPriceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<BalancerWeightedPoolSpotPriceVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_spot_price_oracle_manipulation());
        vulnerabilities.extend(self.detect_weight_ratio_flash_loan_attack());
        vulnerabilities.extend(self.detect_swap_fee_bypass());
        vulnerabilities
    }

    fn detect_spot_price_oracle_manipulation(&self) -> Vec<BalancerWeightedPoolSpotPriceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x04 { // DIV (spot price = (balanceOut/weightOut) / (balanceIn/weightIn))
                let start = if pc > 150 { pc - 150 } else { 0 };
                if self.bytecode[start..pc].iter().filter(|&&b| b == 0x04).count() >= 2 {
                    let has_twap = self.bytecode[start..pc].iter().filter(|&&b| b == 0x42).count() >= 2;
                    if !has_twap {
                        vulns.push(BalancerWeightedPoolSpotPriceVulnerability {
                            pc, vulnerability_type: "SpotPriceOracleManipulation".to_string(),
                            description: format!("Balancer spot price read at PC {} uses instant balances, manipulable via flash loan. Attack: flash loan 10M USDC, swap to WETH in 80/20 pool, spot price skews heavily, oracle reads manipulated price. Real formula: spotPrice = (balanceTokenOut/weightTokenOut) / (balanceTokenIn/weightTokenIn), single swap drastically changes balances. Example: 80/20 WETH/USDC pool with 100 WETH ($200k), 40k USDC, weights 0.8/0.2, attacker swaps 1M USDC for WETH, new balances favor USDC, spot price crashes. Missing: use getTimeWeightedAverage() with sufficient window, not getSpotPrice(). Fix: implement Balancer V2 TWAP oracle with minimum 30-minute window, or use Chainlink price feeds for critical operations.", pc),
                            confidence: 0.89,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_weight_ratio_flash_loan_attack(&self) -> Vec<BalancerWeightedPoolSpotPriceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL (swap)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let has_weight_calc = self.bytecode[start..pc].iter().filter(|&&b| b == 0x04).count() >= 2;
                if has_weight_calc {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let has_max_ratio_check = self.bytecode[pc..window_end].iter().any(|&b| b == 0x10);
                    if !has_max_ratio_check {
                        vulns.push(BalancerWeightedPoolSpotPriceVulnerability {
                            pc, vulnerability_type: "WeightRatioFlashLoanAttack".to_string(),
                            description: format!("Balancer swap at PC {} doesn't check max swap ratio against pool weights, enabling price manipulation. Attack: Balancer math: amountOut = balanceOut * (1 - (balanceIn / (balanceIn + amountIn))^(weightIn/weightOut)), large swaps relative to balance cause extreme price impact. Real attack vector: 90/10 governance token/WETH pool, attacker flash loans to swap 50% of pool balance, weight ratio amplifies price movement. Example: pool has 1M GOV (weight=0.9), 10 WETH (weight=0.1), swap 500k GOV, weight ratio 9:1 magnifies impact, GOV price crashes 80%. Missing: enforce max swap size relative to pool depth, typically 30% of balance. Fix: require amountIn <= balanceIn * MAX_IN_RATIO where MAX_IN_RATIO = 0.3.", pc),
                            confidence: 0.85,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_swap_fee_bypass(&self) -> Vec<BalancerWeightedPoolSpotPriceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x03 { // SUB (fee calculation: amount * (1 - swapFee))
                let start = if pc > 100 { pc - 100 } else { 0 };
                let has_fee_read = self.bytecode[start..pc].iter().any(|&b| b == 0x54);
                if has_fee_read {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let applies_fee = self.bytecode[pc..window_end].iter().any(|&b| b == 0x02);
                    if !applies_fee {
                        vulns.push(BalancerWeightedPoolSpotPriceVulnerability {
                            pc, vulnerability_type: "SwapFeeBypass".to_string(),
                            description: format!("Swap fee calculation at PC {} reads fee but doesn't apply to amount, allowing fee bypass. Attack: protocol integrates Balancer swap, reads swapFeePercentage but doesn't multiply by (1-fee), user receives full swap amount without fees. Real bug: custom router reads pool.getSwapFeePercentage() = 0.003 (0.3%), but forwards full amountIn to swap calculation, pool doesn't charge fee. Missing: amountInAfterFee = amountIn * (1 - swapFeePercentage). Exploit: arbitrage with zero fees while others pay 0.3%, drain pool value via repeated fee-free swaps. Fix: always apply fee before balance calculations: balanceIn += amountIn * (1 - fee).", pc),
                            confidence: 0.77,
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
