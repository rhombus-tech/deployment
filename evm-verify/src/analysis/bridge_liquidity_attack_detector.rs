use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeLiquidityVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct BridgeLiquidityAttackDetector {
    bytecode: Vec<u8>,
}

impl BridgeLiquidityAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<BridgeLiquidityVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_liquidity_pool_drain());
        vulnerabilities.extend(self.detect_asymmetric_liquidity_risk());
        vulnerabilities.extend(self.detect_bridge_fee_manipulation());

        vulnerabilities
    }

    fn detect_liquidity_pool_drain(&self) -> Vec<BridgeLiquidityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (bridge withdrawal)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_balance_check = window.iter().any(|&b| b == 0x47); // SELFBALANCE
                let has_transfer_amount = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_balance_check && has_transfer_amount {
                    let has_liquidity_cap = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    let has_gradual_withdrawal = window.iter().any(|&b| b == 0x42); // TIMESTAMP (rate limit)
                    
                    if !has_liquidity_cap && !has_gradual_withdrawal {
                        vulns.push(BridgeLiquidityVulnerability {
                            pc,
                            vulnerability_type: "LiquidityPoolDrain".to_string(),
                            description: format!(
                                "Bridge withdrawal at PC {} lacks liquidity protection. Attack: bridge holds liquidity pool for fast withdrawals, attacker initiates massive \
                                withdrawal (legitimate or via exploit), drains entire liquidity pool, remaining users cannot withdraw funds until liquidity replenished. Bank \
                                run scenario. Example: bridge holds $100M liquidity, attacker withdraws $90M in single transaction, $900M in pending withdrawals cannot be \
                                processed. Missing: maximum withdrawal per transaction (e.g., 5% of pool), time-based withdrawal limits (e.g., $10M per hour), circuit breakers \
                                on rapid liquidity decrease. Should implement: max_withdrawal = min(requested, pool_balance * 0.05) with graduated delays for large amounts.",
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

    fn detect_asymmetric_liquidity_risk(&self) -> Vec<BridgeLiquidityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (liquidity tracking)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_deposit_logic = window.iter().any(|&b| b == 0x01); // ADD (deposit)
                let has_withdrawal_logic = window.iter().any(|&b| b == 0x03); // SUB (withdrawal)
                
                if has_deposit_logic || has_withdrawal_logic {
                    let has_balance_symmetry_check = window.iter().filter(|&&b| b == 0x54).count() >= 4;
                    let has_cross_chain_sync = window.iter().filter(|&&b| b == 0xF1).count() >= 2;
                    
                    if !has_balance_symmetry_check {
                        vulns.push(BridgeLiquidityVulnerability {
                            pc,
                            vulnerability_type: "AsymmetricLiquidityRisk".to_string(),
                            description: format!(
                                "Bridge liquidity tracking at PC {} doesn't enforce cross-chain balance symmetry. Attack: users deposit to L1 bridge but withdraw from L2, \
                                L1 accumulates deposits, L2 liquidity depletes, eventually L2 cannot honor withdrawals even though L1 is overcollateralized. Liquidity \
                                imbalance. Example: $200M deposited on Ethereum, only $50M on Polygon, users wanting to exit to Ethereum via Polygon bridge hit liquidity \
                                shortage. Missing: cross-chain liquidity rebalancing, asymmetry monitoring, liquidity migration mechanisms. Should implement: automated \
                                liquidity rebalancing when L1_balance > 1.5 * L2_balance, or pause deposits on overweight chain until balanced.",
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

    fn detect_bridge_fee_manipulation(&self) -> Vec<BridgeLiquidityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x04 { // DIV (fee calculation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_amount_based_fee = window.iter().filter(|&&b| b == 0x02).count() >= 1; // MUL
                let has_liquidity_usage = window.iter().any(|&b| b == 0x54); // SLOAD (pool size)
                
                if has_amount_based_fee {
                    let has_oracle_price = window.iter().any(|&b| b == 0xFA); // STATICCALL (oracle)
                    let has_manipulation_resistance = window.iter().filter(|&&b| b == 0x42).count() >= 2; // Time-averaging
                    
                    if has_liquidity_usage && !has_oracle_price {
                        vulns.push(BridgeLiquidityVulnerability {
                            pc,
                            vulnerability_type: "BridgeFeeManipulation".to_string(),
                            description: format!(
                                "Bridge fee calculation at PC {} vulnerable to manipulation. Attack: bridge fees based on pool utilization or on-chain price, attacker \
                                manipulates price/utilization to minimize fees, bridges large amount at low cost, costs externalized to bridge LPs. Example: fee = \
                                0.3% * (1 + utilization_ratio), attacker uses flash loan to temporarily increase opposite-direction liquidity, decreases utilization ratio, \
                                pays lower fee for large bridge. Missing: oracle-based fee calculation, TWAP for utilization metrics, minimum base fee regardless of conditions. \
                                Should use: Chainlink or similar oracle for fee-relevant prices, 24h TWAP for utilization, base_fee = max(0.1%, utilization_based_fee).",
                                pc
                            ),
                            confidence: 0.81,
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
