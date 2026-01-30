use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupEscapeHatchVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct RollupEscapeHatchDetector {
    bytecode: Vec<u8>,
}

impl RollupEscapeHatchDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<RollupEscapeHatchVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_missing_emergency_withdrawal());
        vulnerabilities.extend(self.detect_escape_hatch_griefing());
        vulnerabilities.extend(self.detect_delayed_force_withdrawal());

        vulnerabilities
    }

    fn detect_missing_emergency_withdrawal(&self) -> Vec<RollupEscapeHatchVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (withdrawal execution)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_withdrawal_logic = window.iter().any(|&b| b == 0x03); // SUB (balance decrease)
                let has_rollup_state = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                
                if has_withdrawal_logic {
                    let has_emergency_mode = window.iter().any(|&b| b == 0x54); // SLOAD (emergency flag)
                    let has_direct_l1_exit = window.iter().filter(|&&b| b == 0xF1).count() >= 2;
                    
                    if !has_emergency_mode && !has_direct_l1_exit {
                        vulns.push(RollupEscapeHatchVulnerability {
                            pc,
                            vulnerability_type: "MissingEmergencyWithdrawal".to_string(),
                            description: format!(
                                "Rollup withdrawal at PC {} lacks emergency exit mechanism. Attack scenario: rollup sequencer goes offline or malicious, users cannot process \
                                normal withdrawals through rollup, funds stuck indefinitely with no escape path. User protection failure. Example: zkSync/StarkNet sequencer \
                                stops operating, users have balances but cannot withdraw because sequencer needed for proofs. Missing: L1 emergency withdrawal function allowing \
                                users to directly exit without sequencer, merkle proof based exit, time-delayed force exit. Should implement: function emergencyWithdraw(proof) \
                                allowing users to prove L2 balance on L1 and withdraw directly, activated after sequencer offline for >7 days.",
                                pc
                            ),
                            confidence: 0.90,
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

    fn detect_escape_hatch_griefing(&self) -> Vec<RollupEscapeHatchVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (escape hatch activation)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_emergency_trigger = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                let has_withdrawal_queue = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                
                if has_emergency_trigger {
                    let has_spam_protection = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    let has_queue_limit = window.iter().any(|&b| b == 0x02); // MUL (cost calculation)
                    
                    if !has_spam_protection {
                        vulns.push(RollupEscapeHatchVulnerability {
                            pc,
                            vulnerability_type: "EscapeHatchGriefing".to_string(),
                            description: format!(
                                "Emergency exit mechanism at PC {} vulnerable to griefing. Attack: escape hatch allows anyone to trigger emergency mode or queue forced exits, \
                                attacker spams emergency exit requests with dust amounts, floods withdrawal queue, delays legitimate users, increases operational costs. DoS via \
                                escape hatch abuse. Missing: minimum withdrawal amount for emergency exit, rate limiting per address, exponential cost for queue position. Should \
                                require: emergencyExit() requires min $1000 withdrawal, max 1 exit per address per week, or use priority queue with fees.",
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

    fn detect_delayed_force_withdrawal(&self) -> Vec<RollupEscapeHatchVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP (delay check)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_withdrawal_execution = window.iter().any(|&b| b == 0xF1); // CALL
                let has_force_exit_logic = window.iter().any(|&b| b == 0x55); // SSTORE
                
                if has_withdrawal_execution && has_force_exit_logic {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_reasonable_delay = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    let has_max_delay_cap = pre_window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if !has_max_delay_cap {
                        vulns.push(RollupEscapeHatchVulnerability {
                            pc,
                            vulnerability_type: "DelayedForceWithdrawal".to_string(),
                            description: format!(
                                "Force withdrawal delay at PC {} unbounded or excessive. Attack: rollup implements forced exit but with very long delay (30+ days), user initiates \
                                forced withdrawal, sequencer front-runs by upgrading contract or draining funds before delay expires, user's withdrawal fails. Delay exploitation. \
                                Example: user requests force exit, 30-day timer starts, malicious operator upgrades contract on day 29 to block withdrawal. Missing: reasonable \
                                maximum delay (7-14 days), delay cap enforcement, withdrawal protection during delay period. Should enforce: max force withdrawal delay = 7 days, \
                                lock contract upgrades during pending force withdrawals, or implement immediate exit with slower finality.",
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
