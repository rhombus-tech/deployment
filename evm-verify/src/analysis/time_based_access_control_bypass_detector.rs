use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeBasedAccessVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TimeBasedAccessControlBypassDetector {
    bytecode: Vec<u8>,
}

impl TimeBasedAccessControlBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<TimeBasedAccessVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_block_timestamp_manipulation());
        vulnerabilities.extend(self.detect_time_window_frontrunning());
        vulnerabilities.extend(self.detect_epoch_boundary_exploitation());

        vulnerabilities
    }

    fn detect_block_timestamp_manipulation(&self) -> Vec<TimeBasedAccessVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_access_control = window.iter().any(|&b| b == 0x14); // EQ (time-based check)
                let has_critical_action = window.iter().any(|&b| matches!(b, 0x55 | 0xF1)); // SSTORE or CALL
                
                if has_access_control && has_critical_action {
                    let has_tolerance = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2; // Multiple comparisons
                    let has_block_number_check = window.iter().any(|&b| b == 0x43); // NUMBER
                    
                    if !has_tolerance || !has_block_number_check {
                        vulns.push(TimeBasedAccessVulnerability {
                            pc,
                            vulnerability_type: "BlockTimestampManipulation".to_string(),
                            description: format!(
                                "Time-based access control at PC {} uses block.timestamp for authorization. Miners can manipulate \
                                timestamp by ±15 seconds. Attack: miner adjusts timestamp to fall within restricted time window, \
                                executes privileged action. Missing: timestamp tolerance range, block.number validation, multi-block \
                                verification. Should not rely on exact timestamp for security-critical access control.",
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

    fn detect_time_window_frontrunning(&self) -> Vec<TimeBasedAccessVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let window_end = (pc + 100).min(self.bytecode.len());
                let forward = &self.bytecode[pc..window_end];
                
                let has_window_check = forward.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2; // Range check
                let has_high_value = forward.iter().any(|&b| b == 0x34); // CALLVALUE
                
                if has_window_check && has_high_value {
                    let has_commit_reveal = window.iter().any(|&b| b == 0x20); // KECCAK256
                    let has_randomization = window.iter().any(|&b| b == 0x40); // BLOCKHASH
                    
                    if !has_commit_reveal && !has_randomization {
                        vulns.push(TimeBasedAccessVulnerability {
                            pc,
                            vulnerability_type: "TimeWindowFrontrunning".to_string(),
                            description: format!(
                                "Time window at PC {} predictable and frontrunnableExample: public sale opens at timestamp T, \
                                attacker monitors mempool, frontuns transactions at exactly T. Attack: see others' transactions \
                                attempting to be first in window, submit with higher gas to be included first. Missing: commit-reveal \
                                for window entry, random selection among window participants, anti-frontrunning mechanism.",
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

    fn detect_epoch_boundary_exploitation(&self) -> Vec<TimeBasedAccessVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x06 { // MOD (calculating epoch)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_timestamp = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                let has_epoch_duration = window.windows(2).any(|w| w[0] >= 0x60 && w[0] <= 0x7F); // PUSH constant
                
                if has_timestamp && has_epoch_duration {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_state_change = forward.iter().any(|&b| b == 0x55); // SSTORE
                    
                    if has_state_change {
                        let has_boundary_protection = forward.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                        let has_grace_period = window.iter().filter(|&&b| b == 0x01).count() >= 2; // Multiple ADD
                        
                        if !has_boundary_protection || !has_grace_period {
                            vulns.push(TimeBasedAccessVulnerability {
                                pc,
                                vulnerability_type: "EpochBoundaryExploitation".to_string(),
                                description: format!(
                                    "Epoch calculation at PC {} vulnerable to boundary manipulation. Attack: submit transaction at \
                                    epoch boundary when timestamp % epochDuration ≈ 0, exploit state transition. Example: rewards \
                                    calculated per epoch, claim at boundary to double-count. Missing: grace period at boundaries, \
                                    atomic epoch transitions, boundary timestamp validation. Enables gaming epoch-based mechanics.",
                                    pc
                                ),
                                confidence: 0.83,
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
