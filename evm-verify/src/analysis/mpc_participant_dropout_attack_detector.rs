use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MpcDropoutVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct MpcParticipantDropoutAttackDetector {
    bytecode: Vec<u8>,
}

impl MpcParticipantDropoutAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<MpcDropoutVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_missing_timeout_handling());
        vulnerabilities.extend(self.detect_participant_availability_assumption());
        vulnerabilities.extend(self.detect_partial_computation_vulnerability());

        vulnerabilities
    }

    fn detect_missing_timeout_handling(&self) -> Vec<MpcDropoutVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // External calls to MPC participants
            if matches!(opcode, 0xF1 | 0xFA) {
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check for timestamp-based timeout
                let has_timestamp_check = window.iter().any(|&b| b == 0x42);
                
                // Check for revert/fallback on timeout
                let has_timeout_revert = has_timestamp_check && window.iter().any(|&b| b == 0xFD);
                
                // Check for result validation
                let has_result_check = window.iter().any(|&b| matches!(b, 0x15 | 0x16)); // ISZERO, NOT
                
                if !has_timeout_revert && has_result_check {
                    vulns.push(MpcDropoutVulnerability {
                        pc,
                        vulnerability_type: "MissingTimeoutHandling".to_string(),
                        description: format!(
                            "MPC participant call at PC {} lacks timeout handling for dropout scenarios. \
                            Missing protections: timeout bounds for participant responses, automatic abort \
                            on delayed computation, fallback to alternative participant set. Malicious or \
                            faulty participant can: cause indefinite protocol hang, force restart of expensive \
                            computation, grief other honest participants with wasted resources.",
                            pc
                        ),
                        confidence: 0.86,
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

    fn detect_participant_availability_assumption(&self) -> Vec<MpcDropoutVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut mpc_calls = 0;
        let mut redundancy_checks = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Count MPC participant calls
            if matches!(opcode, 0xF1 | 0xFA) {
                mpc_calls += 1;
            }
            
            // Check for participant redundancy (comparing multiple responses)
            if opcode == 0x14 { // EQ (comparing results)
                let start = if pc > 30 { pc - 30 } else { 0 };
                if self.bytecode[start..pc].iter().filter(|&&b| matches!(b, 0xF1 | 0xFA)).count() >= 2 {
                    redundancy_checks += 1;
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        // If making multiple MPC calls without redundancy
        if mpc_calls >= 2 && redundancy_checks == 0 {
            vulns.push(MpcDropoutVulnerability {
                pc: 0,
                vulnerability_type: "ParticipantAvailabilityAssumption".to_string(),
                description: format!(
                    "MPC protocol makes {} participant calls assuming 100% availability. \
                    No redundancy or fault tolerance for participant dropout. Vulnerable to: \
                    single participant failure halting entire computation, targeted DoS on specific \
                    participants, network partition scenarios. Missing: n-of-m threshold completion, \
                    participant redundancy, dynamic participant replacement. Protocol breaks if any \
                    single participant drops out.",
                    mpc_calls
                ),
                confidence: 0.83,
            });
        }

        vulns
    }

    fn detect_partial_computation_vulnerability(&self) -> Vec<MpcDropoutVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // SSTORE of intermediate MPC results
            if opcode == 0x55 {
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check if storing results from external calls
                let has_external_call = window.iter().any(|&b| matches!(b, 0xF1 | 0xFA));
                
                if has_external_call {
                    // Check for completion validation before storage
                    let has_completion_check = window.windows(3).any(|w| {
                        // Looking for threshold check pattern (comparing count >= minimum)
                        matches!(w[0], 0x10 | 0x11) && w[1] == 0x57 // Comparison + JUMPI
                    });
                    
                    // Check for atomic multi-store (all-or-nothing)
                    let window_end = (pc + 50).min(self.bytecode.len());
                    let forward_window = &self.bytecode[pc..window_end];
                    let has_revert_path = forward_window.iter().any(|&b| b == 0xFD);
                    
                    if !has_completion_check && !has_revert_path {
                        vulns.push(MpcDropoutVulnerability {
                            pc,
                            vulnerability_type: "PartialComputationVulnerability".to_string(),
                            description: format!(
                                "MPC result storage at PC {} accepts partial computation without threshold validation. \
                                Missing enforcement of: minimum participant threshold (t-of-n), result consistency \
                                across participants, atomic commitment of all shares. Attacker can: cause protocol \
                                to accept incomplete MPC output, manipulate result by dropping selective participants, \
                                force restart by withholding final share. Should require threshold validation before commit.",
                                pc
                            ),
                            confidence: 0.88,
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
