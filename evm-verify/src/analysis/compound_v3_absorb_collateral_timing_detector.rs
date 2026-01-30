use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundV3AbsorbVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CompoundV3AbsorbCollateralTimingDetector {
    bytecode: Vec<u8>,
}

impl CompoundV3AbsorbCollateralTimingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CompoundV3AbsorbVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_absorb_frontrun_liquidation());
        vulnerabilities.extend(self.detect_price_update_absorb_sandwich());
        vulnerabilities.extend(self.detect_absorb_reserve_depletion());

        vulnerabilities
    }

    fn detect_absorb_frontrun_liquidation(&self) -> Vec<CompoundV3AbsorbVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (absorb state update)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_absorb_logic = window.iter().filter(|&&b| matches!(b, 0xF1 | 0xFA)).count() >= 2;
                let has_collateral_transfer = window.iter().any(|&b| b == 0x55); // Multiple SSTORE
                
                if has_absorb_logic {
                    let has_absorb_cooldown = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let has_sequence_lock = window.iter().any(|&b| b == 0x43); // NUMBER
                    
                    if !has_absorb_cooldown && !has_sequence_lock {
                        vulns.push(CompoundV3AbsorbVulnerability {
                            pc,
                            vulnerability_type: "AbsorbFrontrunLiquidation".to_string(),
                            description: format!(
                                "Compound V3 absorb() at PC {} has no cooldown, enables frontrunning. Attack: observe liquidation tx in mempool, \
                                frontrun with absorb() call, seize collateral at discounted rate, original liquidator's tx reverts. Absorb is \
                                permissionless and instant. Missing: absorb cooldown period, liquidation priority queue, MEV protection. Should \
                                require minimum time between absorb calls or auction mechanism for liquidations.",
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

    fn detect_price_update_absorb_sandwich(&self) -> Vec<CompoundV3AbsorbVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xFA { // STATICCALL (price oracle)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_absorb_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT (underwater check)
                
                if has_absorb_check {
                    let has_price_staleness = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let has_price_deviation = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 3;
                    
                    if !has_price_staleness {
                        vulns.push(CompoundV3AbsorbVulnerability {
                            pc,
                            vulnerability_type: "PriceUpdateAbsorbSandwich".to_string(),
                            description: format!(
                                "Oracle price check at PC {} for absorb without staleness validation. Attack: (1) Oracle updates price making \
                                position liquidatable, (2) attacker observes price update tx, (3) sandwich: frontrun with absorb(), backrun with \
                                repay, profit from temporary price discrepancy. Missing: price update timestamp check, TWAP instead of spot, \
                                grace period after oracle update. Should delay absorb eligibility after price updates.",
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

    fn detect_absorb_reserve_depletion(&self) -> Vec<CompoundV3AbsorbVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (reserves update)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_reserve_usage = window.iter().any(|&b| b == 0x03); // SUB (reserve decrease)
                let has_absorb_context = window.iter().filter(|&&b| b == 0x54).count() >= 3;
                
                if has_reserve_usage && has_absorb_context {
                    let has_reserve_minimum = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_cap_check = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if !has_reserve_minimum {
                        vulns.push(CompoundV3AbsorbVulnerability {
                            pc,
                            vulnerability_type: "AbsorbReserveDepletion".to_string(),
                            description: format!(
                                "Absorb at PC {} can deplete protocol reserves without limit. Multiple underwater positions absorbed \
                                simultaneously drain reserves, protocol becomes insolvent. Attack: coordinate many undercollateralized \
                                positions, trigger mass absorb event, reserves insufficient to cover losses. Missing: minimum reserve \
                                threshold, absorb pausing when reserves low, reserve replenishment mechanism. Should maintain reserve ratio \
                                above safety threshold.",
                                pc
                            ),
                            confidence: 0.82,
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
