use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorExitVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ValidatorExitQueueManipulationDetector {
    bytecode: Vec<u8>,
}

impl ValidatorExitQueueManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ValidatorExitVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_exit_queue_frontrunning());
        vulnerabilities.extend(self.detect_churn_limit_exploitation());
        vulnerabilities.extend(self.detect_priority_queue_manipulation());

        vulnerabilities
    }

    fn detect_exit_queue_frontrunning(&self) -> Vec<ValidatorExitVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Exit request submission (storage write for queue)
            if opcode == 0x55 { // SSTORE
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for queue position calculation
                let has_queue_index = window.iter().any(|&b| matches!(b, 0x01 | 0x03)); // ADD, SUB
                let has_sload = window.iter().any(|&b| b == 0x54); // SLOAD (reading queue state)
                
                if has_queue_index && has_sload {
                    // Check for frontrunning protection (commitment scheme)
                    let has_commit = window.iter().any(|&b| b == 0x20); // KECCAK256
                    let has_timestamp_lock = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    // Check for queue order enforcement
                    let window_end = (pc + 50).min(self.bytecode.len());
                    let forward_window = &self.bytecode[pc..window_end];
                    let has_position_validation = forward_window.iter().any(|&b| matches!(b, 0x10 | 0x11));
                    
                    if !has_commit && !has_timestamp_lock && !has_position_validation {
                        vulns.push(ValidatorExitVulnerability {
                            pc,
                            vulnerability_type: "ExitQueueFrontrunning".to_string(),
                            description: format!(
                                "Validator exit queue at PC {} vulnerable to frontrunning attacks. \
                                Attack scenario: large validator observes pending exit requests, frontruns with own \
                                exit to capture earlier queue position, exits before unfavorable market conditions. \
                                Missing protections: commit-reveal for exit requests, timestamp-based ordering, \
                                position locking. Enables wealthy validators to always exit first during crises, \
                                unfairly disadvantaging smaller stakers.",
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

    fn detect_churn_limit_exploitation(&self) -> Vec<ValidatorExitVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Churn limit validation (validators per epoch)
            if opcode == 0x04 { // DIV (calculating churn limit)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check if dividing total validators (churn_limit = total_active / CHURN_LIMIT_QUOTIENT)
                let has_total_count = window.iter().any(|&b| b == 0x54); // SLOAD
                
                if has_total_count {
                    // Check for minimum churn limit enforcement
                    let window_end = (pc + 50).min(self.bytecode.len());
                    let forward_window = &self.bytecode[pc..window_end];
                    
                    let has_min_limit = forward_window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    // Check for per-validator limit (prevent whale domination)
                    let has_per_validator_limit = forward_window.windows(2).any(|w| {
                        w[0] == 0x33 && w[1] == 0x54 // CALLER + SLOAD (checking validator's exit count)
                    });
                    
                    if !has_min_limit && !has_per_validator_limit {
                        vulns.push(ValidatorExitVulnerability {
                            pc,
                            vulnerability_type: "ChurnLimitExploitation".to_string(),
                            description: format!(
                                "Churn limit calculation at PC {} lacks per-validator restrictions. \
                                Exploitation: large staking provider controlling many validators can dominate exit queue, \
                                consuming entire epoch's churn limit, blocking other validators from exiting. Economic attack: \
                                during market downturn, large operators exit at better prices while smaller validators trapped. \
                                Missing: per-entity churn limits, fair queue allocation, minimum guaranteed slots per operator.",
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

    fn detect_priority_queue_manipulation(&self) -> Vec<ValidatorExitVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Priority or ordering mechanism
            if opcode == 0x02 { // MUL (priority score calculation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for priority factors (stake amount, duration, etc.)
                let has_balance_factor = window.iter().any(|&b| b == 0x31); // BALANCE
                let has_timestamp_factor = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                
                if has_balance_factor || has_timestamp_factor {
                    // Check for Sybil resistance
                    let has_identity_check = window.iter().any(|&b| b == 0x33); // CALLER
                    
                    // Check for manipulation prevention
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward_window = &self.bytecode[pc..window_end];
                    
                    let has_overflow_protection = forward_window.iter().any(|&b| matches!(b, 0x10 | 0x11));
                    let has_cap = forward_window.iter().any(|&b| b == 0xFD); // REVERT on excessive priority
                    
                    if !has_identity_check && !has_overflow_protection && !has_cap {
                        vulns.push(ValidatorExitVulnerability {
                            pc,
                            vulnerability_type: "PriorityQueueManipulation".to_string(),
                            description: format!(
                                "Exit queue priority calculation at PC {} vulnerable to gaming. \
                                Manipulation vectors: (1) split stake across multiple validators to game priority formula, \
                                (2) time exit requests to maximize priority score, (3) overflow priority calculation for \
                                unfair advantage. Missing safeguards: Sybil-resistant identity, priority score caps, \
                                overflow protection. Enables sophisticated actors to manipulate queue position unfairly.",
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
