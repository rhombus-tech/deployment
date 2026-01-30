use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurveMetapoolVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CurveMetapoolVirtualPriceManipulationDetector {
    bytecode: Vec<u8>,
}

impl CurveMetapoolVirtualPriceManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CurveMetapoolVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_base_pool_virtual_price_attack());
        vulnerabilities.extend(self.detect_amplification_parameter_manipulation());
        vulnerabilities.extend(self.detect_deposit_withdrawal_sandwich());

        vulnerabilities
    }

    fn detect_base_pool_virtual_price_attack(&self) -> Vec<CurveMetapoolVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xFA { // STATICCALL (get_virtual_price from base pool)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_base_pool_call = window.iter().any(|&b| b == 0x20); // KECCAK256 or address
                
                if has_base_pool_call {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_price_validation = forward.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_twap_check = forward.iter().filter(|&&b| b == 0x42).count() >= 2; // Multiple TIMESTAMP
                    
                    if !has_price_validation && !has_twap_check {
                        vulns.push(CurveMetapoolVulnerability {
                            pc,
                            vulnerability_type: "BasePoolVirtualPriceAttack".to_string(),
                            description: format!(
                                "Curve metapool virtual price read at PC {} uses instant base pool price. Attack: (1) flashloan and imbalance base pool \
                                (3Pool), (2) virtual_price() temporarily inflated, (3) deposit to metapool at inflated rate, (4) withdraw from metapool, \
                                (5) rebalance base pool, (6) profit from temporary price manipulation. Missing: TWAP for base pool price, max price deviation \
                                check, base pool balance validation. Should use time-weighted virtual price or cap max deviation.",
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

    fn detect_amplification_parameter_manipulation(&self) -> Vec<CurveMetapoolVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (A parameter)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_d_calculation = window.iter().filter(|&&b| b == 0x02).count() >= 3; // Multiple MUL (D invariant)
                let has_swap_logic = window.iter().any(|&b| b == 0x04); // DIV (price calc)
                
                if has_d_calculation && has_swap_logic {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_a_change_check = pre_window.iter().any(|&b| b == 0x42); // TIMESTAMP (ramp)
                    let has_ramp_validation = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if !has_a_change_check {
                        vulns.push(CurveMetapoolVulnerability {
                            pc,
                            vulnerability_type: "AmplificationParameterManipulation".to_string(),
                            description: format!(
                                "Amplification coefficient (A) usage at PC {} during active ramp. Curve allows A to change over time via ramp_A. Attack: \
                                admin initiates A ramp (e.g., 100 → 200), attacker exploits transition period when A is ramping, D invariant calculation \
                                uses transitional A value, swap prices temporarily off, arbitrage opportunity. Missing: A ramp completion check, price impact \
                                limits during ramp, ramp pause for large swaps. Should restrict large operations during A parameter ramps.",
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

    fn detect_deposit_withdrawal_sandwich(&self) -> Vec<CurveMetapoolVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (balance update)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_add_liquidity = window.iter().filter(|&&b| b == 0x01).count() >= 2; // ADD (deposits)
                let has_lp_mint = window.iter().any(|&b| b == 0x02); // MUL (LP tokens)
                
                if has_add_liquidity && has_lp_mint {
                    let has_slippage_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_deadline = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    if !has_slippage_check || !has_deadline {
                        vulns.push(CurveMetapoolVulnerability {
                            pc,
                            vulnerability_type: "DepositWithdrawalSandwich".to_string(),
                            description: format!(
                                "Liquidity deposit at PC {} without sandwich protection. Curve metapools vulnerable to deposit/withdraw sandwiches. Attack: \
                                (1) observe user's add_liquidity tx, (2) frontrun: imbalance pool via swap, (3) user deposits at worse rate, (4) backrun: \
                                rebalance pool, profit from user's deposit slippage. Missing: minimum LP tokens check, deadline protection, deposit bonus \
                                validation. Should enforce: require(LP_received >= minAmount && block.timestamp <= deadline).",
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
