use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitingTimeVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct RateLimitingTimeManipulationDetector {
    bytecode: Vec<u8>,
}

impl RateLimitingTimeManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<RateLimitingTimeVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_cooldown_reset_exploit());
        vulnerabilities.extend(self.detect_rate_limit_sybil_bypass());
        vulnerabilities.extend(self.detect_timelock_early_execution());

        vulnerabilities
    }

    fn detect_cooldown_reset_exploit(&self) -> Vec<RateLimitingTimeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP (cooldown check)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_last_action = window.iter().any(|&b| b == 0x54); // SLOAD (last action time)
                let has_user_id = window.iter().any(|&b| b == 0x33); // CALLER
                
                if has_last_action && has_user_id {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_comparison = forward.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_update = forward.iter().any(|&b| b == 0x55); // SSTORE (updating last time)
                    
                    if has_comparison && has_update {
                        let has_atomic_check_update = forward.iter().filter(|&&b| b == 0x57).count() >= 2; // JUMPI checks
                        
                        if !has_atomic_check_update {
                            vulns.push(RateLimitingTimeVulnerability {
                                pc,
                                vulnerability_type: "CooldownResetExploit".to_string(),
                                description: format!(
                                    "Cooldown check at PC {} vulnerable to reset manipulation. Attack: send transaction that passes \
                                    cooldown check but reverts before updating lastActionTime, cooldown not consumed, retry immediately. \
                                    Missing: atomic check-and-update, state change before check, revert-safe cooldown tracking. \
                                    Enables bypassing rate limits through controlled reverts.",
                                    pc
                                ),
                                confidence: 0.86,
                            });
                        }
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

    fn detect_rate_limit_sybil_bypass(&self) -> Vec<RateLimitingTimeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (recording action)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_timestamp = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                let has_user = window.iter().any(|&b| b == 0x33); // CALLER
                
                if has_timestamp && has_user {
                    let has_balance_requirement = window.iter().any(|&b| matches!(b, 0x31 | 0x54)); // BALANCE, SLOAD
                    let has_aggregation = window.iter().any(|&b| b == 0x01); // ADD (cumulative tracking)
                    
                    if !has_balance_requirement && !has_aggregation {
                        vulns.push(RateLimitingTimeVulnerability {
                            pc,
                            vulnerability_type: "RateLimitSybilBypass".to_string(),
                            description: format!(
                                "Rate limiting at PC {} uses per-address tracking without Sybil resistance. Attack: create multiple \
                                addresses, each gets full rate limit, circumventing global limits. Example: 1 action per address per day \
                                = unlimited actions via unlimited addresses. Missing: IP/identity verification, stake requirement, \
                                cross-address aggregation. Rate limits should be Sybil-resistant for security effectiveness.",
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

    fn detect_timelock_early_execution(&self) -> Vec<RateLimitingTimeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP (timelock check)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_execution_time = window.iter().any(|&b| b == 0x54); // SLOAD (scheduled time)
                
                if has_execution_time {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_comparison = forward.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_execution = forward.iter().any(|&b| matches!(b, 0xF1 | 0xF4)); // CALL, DELEGATECALL
                    
                    if has_comparison && has_execution {
                        let is_gte = forward.windows(2).any(|w| w[0] == 0x10 && w[1] == 0x15); // LT + ISZERO (>=)
                        let has_equality_only = forward.iter().filter(|&&b| b == 0x14).count() > 0; // EQ
                        
                        if !is_gte && !has_equality_only {
                            vulns.push(RateLimitingTimeVulnerability {
                                pc,
                                vulnerability_type: "TimelockEarlyExecution".to_string(),
                                description: format!(
                                    "Timelock at PC {} uses wrong comparison operator. Should be >= (timestamp >= unlockTime), but might \
                                    use > allowing early execution. Attack: execute 1 second before intended unlock time due to off-by-one. \
                                    Missing: correct >= comparison, comprehensive timing tests, boundary condition validation. \
                                    Timelock should enforce exact or later execution, never earlier.",
                                    pc
                                ),
                                confidence: 0.88,
                            });
                        }
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
