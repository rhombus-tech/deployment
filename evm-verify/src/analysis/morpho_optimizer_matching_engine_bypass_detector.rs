use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MorphoOptimizerVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct MorphoOptimizerMatchingEngineBypassDetector {
    bytecode: Vec<u8>,
}

impl MorphoOptimizerMatchingEngineBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<MorphoOptimizerVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_p2p_matching_bypass());
        vulnerabilities.extend(self.detect_promotion_demotion_manipulation());
        vulnerabilities.extend(self.detect_delta_mechanism_griefing());

        vulnerabilities
    }

    fn detect_p2p_matching_bypass(&self) -> Vec<MorphoOptimizerVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (matching state)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_matching_logic = window.iter().filter(|&&b| b == 0x54).count() >= 3; // Multiple SLOAD
                let has_p2p_rate = window.iter().any(|&b| b == 0x02); // MUL (rate calculation)
                
                if has_matching_logic {
                    let has_pool_fallback_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_matching_threshold = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if !has_matching_threshold {
                        vulns.push(MorphoOptimizerVulnerability {
                            pc,
                            vulnerability_type: "P2PMatchingBypass".to_string(),
                            description: format!(
                                "Morpho P2P matching at PC {} lacks minimum threshold enforcement. Attack: deposit/borrow tiny amounts \
                                repeatedly to avoid P2P matching, stay in pool with worse rates, grief other users waiting for matches. \
                                Or: flash loan large amount, trigger matching for brief period, withdraw, unmatched users stuck at pool \
                                rates. Missing: minimum amount for P2P matching, matching stability period. Should require minAmount and \
                                prevent immediate unmatch after match.",
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

    fn detect_promotion_demotion_manipulation(&self) -> Vec<MorphoOptimizerVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (promotion/demotion)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_delta_update = window.iter().any(|&b| b == 0x03); // SUB (delta change)
                let has_promotion_logic = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                
                if has_promotion_logic {
                    let has_gas_check = window.iter().any(|&b| b == 0x5A); // GAS
                    let has_max_iterations = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // Loop limit
                    
                    if !has_gas_check && !has_max_iterations {
                        vulns.push(MorphoOptimizerVulnerability {
                            pc,
                            vulnerability_type: "PromotionDemotionManipulation".to_string(),
                            description: format!(
                                "Promotion/demotion at PC {} without gas limit. Morpho promotes users from pool to P2P when liquidity available. \
                                Attack: create many small positions, trigger promotion iteration over thousands of users, exhaust gas, DoS the \
                                protocol. Or: strategic timing of withdraw to force demotion during high gas, grief matched users. Missing: \
                                maximum iterations per promotion/demotion, gas reservation check. Should cap promotion batches to prevent DoS.",
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

    fn detect_delta_mechanism_griefing(&self) -> Vec<MorphoOptimizerVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x03 { // SUB (delta calculation)
                let window_end = (pc + 60).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_delta_storage = window.iter().any(|&b| b == 0x55); // SSTORE
                
                if has_delta_storage {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_p2p_supply = pre_window.iter().any(|&b| b == 0x54); // SLOAD
                    let has_delta_cap = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if has_p2p_supply && !has_delta_cap {
                        vulns.push(MorphoOptimizerVulnerability {
                            pc,
                            vulnerability_type: "DeltaMechanismGriefing".to_string(),
                            description: format!(
                                "Delta update at PC {} allows unbounded delta growth. Delta = unmatched liquidity on pool. Attack: repeatedly \
                                supply/withdraw to pool side without P2P matching, inflate delta massively, when someone wants to match P2P they \
                                must process huge delta first, gas costs prohibitive. Missing: maximum delta per market, delta reduction incentive, \
                                rate limiting on delta-increasing operations. Should cap delta growth to prevent griefing.",
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
