use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtlcTimelockVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct HtlcTimelockExpiryGriefingDetector {
    bytecode: Vec<u8>,
}

impl HtlcTimelockExpiryGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<HtlcTimelockVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unprotected_timelock_expiry());
        vulnerabilities.extend(self.detect_griefing_via_delayed_claim());
        vulnerabilities.extend(self.detect_asymmetric_timelock_windows());

        vulnerabilities
    }

    fn detect_unprotected_timelock_expiry(&self) -> Vec<HtlcTimelockVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // TIMESTAMP comparison for timelock
            if opcode == 0x42 {
                let mut check_pc = pc + 1;
                let mut has_comparison = false;
                let mut has_revert_on_expired = false;
                let mut instructions = 0;

                while check_pc < self.bytecode.len() && instructions < 40 {
                    let check_op = self.bytecode[check_pc];
                    
                    if matches!(check_op, 0x10 | 0x11) { // LT, GT
                        has_comparison = true;
                    }
                    
                    // Check for JUMPI (conditional execution) without REVERT
                    if check_op == 0x57 { // JUMPI
                        // Look ahead for REVERT
                        let ahead_end = (check_pc + 20).min(self.bytecode.len());
                        has_revert_on_expired = self.bytecode[check_pc..ahead_end].iter().any(|&b| b == 0xFD);
                    }
                    
                    check_pc += 1;
                    instructions += 1;
                    
                    if check_op >= 0x60 && check_op <= 0x7F {
                        check_pc += (check_op - 0x5F) as usize;
                    }
                }

                if has_comparison && !has_revert_on_expired {
                    vulns.push(HtlcTimelockVulnerability {
                        pc,
                        vulnerability_type: "UnprotectedTimelockExpiry".to_string(),
                        description: format!(
                            "HTLC timelock check at PC {} without proper expiry enforcement. \
                            Missing revert on expired timelock allows: griefing by intentionally \
                            delaying claim until after expiry, forcing counterparty to wait for refund \
                            period, and locking funds unnecessarily. Enables denial-of-service attacks.",
                            pc
                        ),
                        confidence: 0.89,
                    });
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_griefing_via_delayed_claim(&self) -> Vec<HtlcTimelockVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for hash preimage verification (KECCAK256 followed by EQ)
            if opcode == 0x20 { // KECCAK256
                let window_end = (pc + 30).min(self.bytecode.len());
                let has_eq_check = self.bytecode[pc..window_end].iter().any(|&b| b == 0x14);
                
                if has_eq_check {
                    // Check if there's timelock validation BEFORE transfer
                    let start = if pc > 60 { pc - 60 } else { 0 };
                    let window = &self.bytecode[start..pc];
                    
                    let has_timelock_check = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    // Look for transfer after hash check
                    let has_transfer = self.bytecode[pc..window_end].iter().any(|&b| matches!(b, 0xF1 | 0xF0)); // CALL, CREATE
                    
                    if !has_timelock_check && has_transfer {
                        vulns.push(HtlcTimelockVulnerability {
                            pc,
                            vulnerability_type: "GriefingViaDelayedClaim".to_string(),
                            description: format!(
                                "HTLC claim at PC {} allows griefing through delayed preimage revelation. \
                                Attacker can: wait until just before expiry to reveal preimage, force \
                                counterparty to monitor contract continuously, cause maximum waiting period \
                                for refund, and extract griefing value without economic cost.",
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

    fn detect_asymmetric_timelock_windows(&self) -> Vec<HtlcTimelockVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut timelock_constants = Vec::new();

        // Collect all time constants from PUSH operations
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for PUSH2 or PUSH3 with time-like values (86400 = 1 day, 3600 = 1 hour)
            if matches!(opcode, 0x61 | 0x62) && pc + 3 < self.bytecode.len() {
                let value = if opcode == 0x61 {
                    u16::from_be_bytes([self.bytecode[pc + 1], self.bytecode[pc + 2]]) as u32
                } else {
                    u32::from_be_bytes([0, self.bytecode[pc + 1], self.bytecode[pc + 2], self.bytecode[pc + 3]])
                };
                
                // Filter for time-like constants (hours to days range)
                if value >= 3600 && value <= 86400 * 7 {
                    timelock_constants.push((pc, value));
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        // Check for asymmetric timelocks (significant difference between two values)
        if timelock_constants.len() >= 2 {
            for i in 0..timelock_constants.len() - 1 {
                for j in i + 1..timelock_constants.len() {
                    let (pc1, val1) = timelock_constants[i];
                    let (_, val2) = timelock_constants[j];
                    
                    let ratio = if val1 > val2 {
                        val1 as f32 / val2 as f32
                    } else {
                        val2 as f32 / val1 as f32
                    };
                    
                    // If one timelock is more than 3x the other, flag as asymmetric
                    if ratio > 3.0 {
                        vulns.push(HtlcTimelockVulnerability {
                            pc: pc1,
                            vulnerability_type: "AsymmetricTimelockWindows".to_string(),
                            description: format!(
                                "HTLC has asymmetric timelock windows at PC {} ({} vs {} seconds, ratio: {:.1}x). \
                                Favors one party with significantly longer claim window. Enables: unfair advantage \
                                in claim timing, increased griefing opportunity for privileged party, and \
                                economic imbalance in cross-chain atomic swaps.",
                                pc1, val1, val2, ratio
                            ),
                            confidence: 0.82,
                        });
                        break;
                    }
                }
            }
        }

        vulns
    }
}
