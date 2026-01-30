use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorReputationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ValidatorReputationManipulationDetector {
    bytecode: Vec<u8>,
}

impl ValidatorReputationManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ValidatorReputationVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_sybil_reputation_gaming());
        vulnerabilities.extend(self.detect_uptime_metric_manipulation());
        vulnerabilities.extend(self.detect_attestation_performance_spoofing());

        vulnerabilities
    }

    fn detect_sybil_reputation_gaming(&self) -> Vec<ValidatorReputationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Reputation score update (SSTORE)
            if opcode == 0x55 {
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for reputation calculation
                let has_arithmetic = window.iter().any(|&b| matches!(b, 0x01 | 0x02 | 0x03 | 0x04)); // ADD, MUL, SUB, DIV
                
                if has_arithmetic {
                    // Check for Sybil resistance (validator uniqueness)
                    let has_unique_id = window.iter().any(|&b| b == 0x33); // CALLER
                    let has_stake_weight = window.iter().any(|&b| b == 0x31); // BALANCE
                    
                    // Check for identity clustering detection
                    let has_clustering_check = window.iter().any(|&b| b == 0x18); // XOR (address similarity)
                    
                    // Check for cross-validator correlation
                    let sload_count = window.iter().filter(|&&b| b == 0x54).count();
                    
                    if !has_stake_weight && !has_clustering_check && sload_count < 2 {
                        vulns.push(ValidatorReputationVulnerability {
                            pc,
                            vulnerability_type: "SybilReputationGaming".to_string(),
                            description: format!(
                                "Reputation score update at PC {} vulnerable to Sybil attacks. \
                                Missing Sybil resistance: operator can run multiple validators to game reputation system, \
                                each validator gets independent reputation boost. Without stake-weighting or identity clustering: \
                                100 low-stake validators appear better than 1 high-stake validator. Enables: manipulation of \
                                validator selection algorithms, unfair delegation attraction, protocol influence concentration.",
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

    fn detect_uptime_metric_manipulation(&self) -> Vec<ValidatorReputationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Uptime tracking (timestamp-based calculations)
            if opcode == 0x42 { // TIMESTAMP
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check for uptime calculation (time delta)
                let has_sub = window.iter().any(|&b| b == 0x03); // SUB
                let has_sstore = window.iter().any(|&b| b == 0x55); // SSTORE
                
                if has_sub && has_sstore {
                    // Check for missed attestation tracking
                    let start = if pc > 60 { pc - 60 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_attestation_check = pre_window.iter().any(|&b| b == 0x54); // SLOAD (checking attestations)
                    
                    // Check for strategic downtime detection
                    let has_pattern_analysis = window.iter().any(|&b| b == 0x20); // KECCAK256 (heuristic patterns)
                    
                    // Check for minimum uptime requirement
                    let has_threshold = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if !has_attestation_check && !has_pattern_analysis && !has_threshold {
                        vulns.push(ValidatorReputationVulnerability {
                            pc,
                            vulnerability_type: "UptimeMetricManipulation".to_string(),
                            description: format!(
                                "Uptime tracking at PC {} measures time-online without attestation quality. \
                                Manipulation: validator stays online but performs no duties (ghost validator), or strategically \
                                goes offline during unfavorable conditions (avoiding difficult attestations). Missing detection: \
                                actual attestation participation vs. mere connectivity, strategic downtime patterns, quality-weighted \
                                uptime. Enables gaming: appear highly available while contributing minimally.",
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

    fn detect_attestation_performance_spoofing(&self) -> Vec<ValidatorReputationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Attestation submission/verification
            if opcode == 0x01 || opcode == 0x08 { // ECRECOVER or bn256Pairing
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for attestation data
                let has_attestation_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_attestation_data {
                    // Check for attestation correctness validation
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward_window = &self.bytecode[pc..window_end];
                    
                    let has_correctness_check = forward_window.iter().any(|&b| b == 0x14); // EQ (checking against truth)
                    
                    // Check for timing analysis (late attestations worth less)
                    let has_timing = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    // Check for majority vote validation
                    let has_consensus_check = window.iter().any(|&b| matches!(b, 0x04 | 0x05)); // DIV, SDIV (calculating majority)
                    
                    if !has_correctness_check && !has_timing && !has_consensus_check {
                        vulns.push(ValidatorReputationVulnerability {
                            pc,
                            vulnerability_type: "AttestationPerformanceSpoofing".to_string(),
                            description: format!(
                                "Attestation performance tracking at PC {} credits submissions without quality validation. \
                                Spoofing attacks: (1) submit attestations with incorrect data (counts as participation), \
                                (2) consistently attest late but still get credit, (3) always vote with majority without \
                                independent validation. Missing metrics: attestation correctness rate, inclusion distance, \
                                vote uniqueness/independence. Rewards validators for quantity over quality of attestations.",
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
