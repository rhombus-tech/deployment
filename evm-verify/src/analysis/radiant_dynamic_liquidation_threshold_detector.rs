use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadiantLiquidationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct RadiantDynamicLiquidationThresholdDetector {
    bytecode: Vec<u8>,
}

impl RadiantDynamicLiquidationThresholdDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<RadiantLiquidationVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_dlp_lock_timing_exploit());
        vulnerabilities.extend(self.detect_threshold_manipulation_via_vesting());
        vulnerabilities.extend(self.detect_liquidation_bonus_griefing());

        vulnerabilities
    }

    fn detect_dlp_lock_timing_exploit(&self) -> Vec<RadiantLiquidationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (DLP lock update)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_lock_amount = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_threshold_calc = window.iter().any(|&b| b == 0x02); // MUL
                
                if has_lock_amount && has_threshold_calc {
                    let has_lock_duration_check = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let has_immediate_effect = !window.iter().any(|&b| b == 0x01); // No ADD (delay)
                    
                    if has_immediate_effect {
                        vulns.push(RadiantLiquidationVulnerability {
                            pc,
                            vulnerability_type: "DLPLockTimingExploit".to_string(),
                            description: format!(
                                "Radiant DLP (Dynamic Liquidation Penalty) lock at PC {} takes immediate effect. Attack: position approaching \
                                liquidation threshold, deposit DLP tokens to instantly increase threshold, avoid liquidation. Then unlock DLP after \
                                price recovers. Or: flash loan DLP tokens, lock during liquidation tx, unlock after, liquidator loses gas. Missing: \
                                DLP lock grace period, vesting schedule for threshold increase, unlock cooldown. Should delay threshold boost to \
                                prevent manipulation.",
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

    fn detect_threshold_manipulation_via_vesting(&self) -> Vec<RadiantLiquidationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x02 { // MUL (threshold calculation)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_vested_amount = window.iter().any(|&b| b == 0x54); // SLOAD (vesting state)
                let has_threshold_multiplier = window.iter().any(|&b| b == 0x02); // Another MUL
                
                if has_vested_amount {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_unvested_penalty = forward.iter().any(|&b| b == 0x03); // SUB
                    
                    if !has_unvested_penalty {
                        vulns.push(RadiantLiquidationVulnerability {
                            pc,
                            vulnerability_type: "ThresholdManipulationViaVesting".to_string(),
                            description: format!(
                                "Liquidation threshold at PC {} counts unvested DLP at full value. Radiant uses vesting DLP to determine threshold. \
                                Attack: claim DLP rewards (unvested), immediately gain full threshold boost, borrow maximum, liquidation protection \
                                from tokens that can't be sold yet. Unfair advantage over vested users. Missing: vested-only threshold calculation, \
                                linear vesting credit, cliff period before threshold boost. Should only count fully vested DLP for liquidation protection.",
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

    fn detect_liquidation_bonus_griefing(&self) -> Vec<RadiantLiquidationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (liquidation)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_liquidation = window.iter().any(|&b| matches!(b, 0xF1 | 0xF4)); // CALL, DELEGATECALL
                let has_bonus_calc = window.iter().filter(|&&b| b == 0x02).count() >= 2; // Multiple MUL
                
                if has_liquidation && has_bonus_calc {
                    let has_dlp_bonus_check = window.iter().any(|&b| b == 0x54); // SLOAD (DLP state)
                    let has_bonus_cap = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if has_dlp_bonus_check && !has_bonus_cap {
                        vulns.push(RadiantLiquidationVulnerability {
                            pc,
                            vulnerability_type: "LiquidationBonusGriefing".to_string(),
                            description: format!(
                                "Liquidation bonus at PC {} scales with DLP without cap. Attack: borrower locks massive DLP amount, creates high \
                                liquidation threshold (90%+), intentionally gets liquidated at 91%, liquidator receives huge bonus (15%+), borrower \
                                colludes with liquidator to extract value from protocol reserves. Or: DLP whale manipulation creates unfair liquidation \
                                economics. Missing: maximum liquidation bonus cap, bonus independent of DLP amount, progressive penalty structure. \
                                Should cap bonus to prevent manipulation.",
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
