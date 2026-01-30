use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraderJoeBinVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TraderJoeLiquidityBookBinManipulationDetector {
    bytecode: Vec<u8>,
}

impl TraderJoeLiquidityBookBinManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<TraderJoeBinVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_active_bin_manipulation());
        vulnerabilities.extend(self.detect_bin_step_gaming());
        vulnerabilities.extend(self.detect_liquidity_distribution_attack());

        vulnerabilities
    }

    fn detect_active_bin_manipulation(&self) -> Vec<TraderJoeBinVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (active bin update)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_swap_logic = window.iter().filter(|&&b| matches!(b, 0x01 | 0x03)).count() >= 3; // ADD, SUB
                let has_bin_calculation = window.iter().any(|&b| b == 0x02); // MUL (bin math)
                
                if has_swap_logic && has_bin_calculation {
                    let has_slippage_protection = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_active_bin_lock = window.iter().filter(|&&b| b == 0x55).count() >= 3;
                    
                    if !has_slippage_protection {
                        vulns.push(TraderJoeBinVulnerability {
                            pc,
                            vulnerability_type: "ActiveBinManipulation".to_string(),
                            description: format!(
                                "Trader Joe V2 active bin update at PC {} without slippage protection. Liquidity Book uses discrete bins for concentrated \
                                liquidity. Attack: large swap moves active bin (current price bin), subsequent swaps execute in wrong bin, users get worse \
                                prices than expected. Attacker profits by: (1) move active bin with large swap, (2) victim swaps at manipulated bin, (3) \
                                revert original swap. Missing: max active bin movement limit, bin crossing validation. Should enforce: abs(newActiveBin - \
                                oldActiveBin) <= maxBinCrossing.",
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

    fn detect_bin_step_gaming(&self) -> Vec<TraderJoeBinVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (bin step parameter)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_price_calculation = window.iter().filter(|&&b| b == 0x02).count() >= 2; // MUL (price from bin)
                let has_fee_calculation = window.iter().any(|&b| b == 0x04); // DIV
                
                if has_price_calculation {
                    let has_bin_step_validation = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // Range check
                    
                    if !has_bin_step_validation {
                        vulns.push(TraderJoeBinVulnerability {
                            pc,
                            vulnerability_type: "BinStepGaming".to_string(),
                            description: format!(
                                "Bin step usage at PC {} without validation. Trader Joe bin step determines price granularity (1 basis point per bin). Attack: \
                                create pool with extreme bin step (e.g., 1 bp vs 100 bp), users don't notice parameter difference, swap at disadvantageous \
                                granularity, MEV bots exploit price gaps between bins. Missing: bin step bounds check, bin step display/warning, standard \
                                bin step enforcement. Should validate: binStep in [MIN_BIN_STEP, MAX_BIN_STEP] or use standard values (1, 5, 10, 25, 50, 100).",
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

    fn detect_liquidity_distribution_attack(&self) -> Vec<TraderJoeBinVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (bin liquidity update)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_add_liquidity = window.iter().any(|&b| b == 0x01); // ADD
                let has_multiple_bins = window.iter().filter(|&&b| b == 0x20).count() >= 2; // KECCAK256 (bin slots)
                
                if has_add_liquidity && has_multiple_bins {
                    let has_distribution_validation = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 3;
                    let has_total_liquidity_check = window.iter().filter(|&&b| b == 0x54).count() >= 3;
                    
                    if !has_distribution_validation {
                        vulns.push(TraderJoeBinVulnerability {
                            pc,
                            vulnerability_type: "LiquidityDistributionAttack".to_string(),
                            description: format!(
                                "Multi-bin liquidity deposit at PC {} without distribution validation. Users deposit across multiple bins for range orders. \
                                Attack: malicious distribution parameter (deltaIds) puts all liquidity in single bin far from active, user thinks they provided \
                                wide range but actually have no active liquidity, LP tokens minted based on total amount not distribution. Missing: distribution \
                                uniformity check, active bin proximity requirement, bin count validation. Should verify: liquidity distribution matches user \
                                expectations, bins near active bin.",
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
}
