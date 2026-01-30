use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerBypassVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CircuitBreakerBypassViaReentrancyDetector {
    bytecode: Vec<u8>,
}

impl CircuitBreakerBypassViaReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CircuitBreakerBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_circuit_breaker_state_reentrancy());
        vulnerabilities.extend(self.detect_threshold_check_timing());
        vulnerabilities.extend(self.detect_emergency_mode_bypass());
        vulnerabilities
    }

    fn detect_circuit_breaker_state_reentrancy(&self) -> Vec<CircuitBreakerBypassVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x54 { // SLOAD (circuit breaker state read)
                let window_end = (pc + 100).min(self.bytecode.len());
                let has_threshold_check = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x10).count() >= 1;
                if has_threshold_check {
                    let followed_by_call = self.bytecode[pc..window_end].iter().any(|&b| b == 0xF1);
                    if followed_by_call {
                        let state_updated_after = self.bytecode[pc..window_end].iter().any(|&b| b == 0x55);
                        if !state_updated_after {
                            vulns.push(CircuitBreakerBypassVulnerability {
                                pc, vulnerability_type: "CircuitBreakerStateReentrancy".to_string(),
                                description: format!("Circuit breaker check at PC {} doesn't update state before external call, allowing bypass via reentrancy. Attack: contract checks if withdrawal limit exceeded, limit not exceeded, makes external call, callee reenters, circuit breaker state unchanged, second withdrawal approved, total exceeds limit. Real attack: function withdraw() checks dailyWithdrawn < DAILY_LIMIT, passes check (dailyWithdrawn = 900, limit = 1000), calls user.send(100), user reenters withdraw(), dailyWithdrawn still 900, second withdrawal of 100 approved, total = 1000, both succeed, limit bypassed. Example: protocol has circuit breaker limiting swaps to 1M per hour, swap() checks hourlyVolume < 1M, passes (900K), calls external pool, pool reenters swap(), hourlyVolume still 900K, second swap of 200K approved, total 1.1M exceeds limit. Missing: update state before external call, reentrancy guard on circuit breaker check. Should implement: dailyWithdrawn += amount before external call. Fix: use checks-effects-interactions pattern, update circuit breaker state before external calls, add nonReentrant modifier to functions with circuit breakers.", pc),
                                confidence: 0.88,
                            });
                        }
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_threshold_check_timing(&self) -> Vec<CircuitBreakerBypassVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x10 { // LT (threshold comparison)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let compares_accumulator = self.bytecode[start..pc].iter().filter(|&&b| b == 0x54).count() >= 2;
                if compares_accumulator {
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let has_revert = self.bytecode[pc..window_end].iter().any(|&b| b == 0xFD);
                    let updates_after_check = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x55).count() >= 1;
                    if has_revert && !updates_after_check {
                        vulns.push(CircuitBreakerBypassVulnerability {
                            pc, vulnerability_type: "ThresholdCheckTiming".to_string(),
                            description: format!("Threshold check at PC {} reverts without updating state, allowing repeated bypass attempts. Attack: circuit breaker checks threshold, reverts if exceeded, state not updated on revert, attacker retries until threshold resets, drains funds in time window. Real vulnerability: hourly withdrawal limit, check fails at 59:59, reverts without updating lastCheckTime, attacker waits 1 second until 60:00, limit resets, immediately withdraws full amount. Example: protocol limits TVL growth to 10% per hour, deposit() checks if newTVL > oldTVL * 1.1, reverts if true, but doesn't record attempt timestamp, attacker attempts deposits every second, succeeds right after hour boundary. Missing: update check timestamp even on revert, implement rate limiting. Should implement: lastAttemptTime = block.timestamp even when reverting. Fix: use two-step pattern where state updated before check, or record all attempts regardless of outcome, implement exponential backoff for failed attempts.", pc),
                            confidence: 0.81,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_emergency_mode_bypass(&self) -> Vec<CircuitBreakerBypassVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x15 { // ISZERO (emergency mode check)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let checks_emergency_flag = self.bytecode[start..pc].iter().any(|&b| b == 0x54);
                if checks_emergency_flag {
                    let window_end = (pc + 120).min(self.bytecode.len());
                    let has_external_call = self.bytecode[pc..window_end].iter().filter(|&&b| matches!(b, 0xF1 | 0xF4)).count() >= 1;
                    if has_external_call {
                        let flag_set_atomically = self.bytecode[start..window_end].iter().filter(|&&b| b == 0x55).count() >= 1;
                        if !flag_set_atomically {
                            vulns.push(CircuitBreakerBypassVulnerability {
                                pc, vulnerability_type: "EmergencyModeBypass".to_string(),
                                description: format!("Emergency mode check at PC {} doesn't set flag atomically before external call, allowing bypass. Attack: emergency mode triggered by external condition, flag checked but not set before external call, callee manipulates condition back to normal, emergency mode bypassed. Real attack: protocol pauses if oracle price deviates >10%, function checks !paused, calls external oracle, oracle contract reenters, manipulates price back within 10%, paused flag still false, withdraw proceeds. Example: circuit breaker triggers if TVL drops 50%, withdraw() checks !emergencyMode, calls user.transfer(), user reenters depositing funds, TVL restored, emergencyMode false, second withdraw succeeds. Missing: set emergency flag immediately, atomic flag + call, reentrancy protection. Should implement: emergencyMode = true before any external calls when condition met. Fix: use pull pattern for withdrawals instead of push, set all emergency flags before external interactions, add nonReentrant to emergency-sensitive functions.", pc),
                                confidence: 0.79,
                            });
                        }
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
