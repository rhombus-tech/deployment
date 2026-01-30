use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingAmbiguityVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct SlashingConditionAmbiguityDetector {
    bytecode: Vec<u8>,
}

impl SlashingConditionAmbiguityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SlashingAmbiguityVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_undefined_slashing_conditions());
        vulnerabilities.extend(self.detect_proof_verification_ambiguity());
        vulnerabilities.extend(self.detect_slashing_amount_calculation_inconsistency());

        vulnerabilities
    }

    fn detect_undefined_slashing_conditions(&self) -> Vec<SlashingAmbiguityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Slashing execution (stake reduction)
            if opcode == 0x03 { // SUB (reducing stake)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for slashing trigger conditions
                let has_condition_check = window.iter().any(|&b| matches!(b, 0x14 | 0x10 | 0x11)); // EQ, LT, GT
                
                if has_condition_check {
                    // Check for explicit condition documentation/validation
                    // Look for multiple condition checks (well-defined criteria)
                    let condition_count = window.iter().filter(|&&b| matches!(b, 0x14 | 0x10 | 0x11)).count();
                    
                    // Check for dispute resolution mechanism
                    let has_timestamp_lock = window.iter().any(|&b| b == 0x42); // TIMESTAMP (appeal period)
                    let has_governance_override = window.iter().any(|&b| b == 0x33); // CALLER (admin intervention)
                    
                    if condition_count < 2 && !has_timestamp_lock && !has_governance_override {
                        vulns.push(SlashingAmbiguityVulnerability {
                            pc,
                            vulnerability_type: "UndefinedSlashingConditions".to_string(),
                            description: format!(
                                "Slashing execution at PC {} with ambiguous trigger conditions ({} checks). \
                                Risks: (1) validators uncertain what behavior causes slashing, (2) subjective interpretation \
                                enables unfair penalties, (3) no dispute resolution for borderline cases. Missing: \
                                explicit multi-factor validation, appeal mechanism, governance review for edge cases. \
                                Validators face unpredictable slashing risk, harming decentralization.",
                                pc, condition_count
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

    fn detect_proof_verification_ambiguity(&self) -> Vec<SlashingAmbiguityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Slashing proof verification (signature or ZK proof)
            if opcode == 0x01 || opcode == 0x08 { // ECRECOVER or bn256Pairing
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for proof submission
                let has_proof_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_proof_data {
                    // Check for proof format validation
                    let has_length_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    // Check for multiple proof requirement (preventing false accusations)
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward_window = &self.bytecode[pc..window_end];
                    
                    let proof_count = forward_window.iter().filter(|&&b| matches!(b, 0x01 | 0x08)).count();
                    
                    // Check for timeout/validity period
                    let has_validity_check = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    if !has_length_check && proof_count < 2 && !has_validity_check {
                        vulns.push(SlashingAmbiguityVulnerability {
                            pc,
                            vulnerability_type: "ProofVerificationAmbiguity".to_string(),
                            description: format!(
                                "Slashing proof verification at PC {} accepts insufficiently validated evidence. \
                                Single proof without corroboration enables false slashing accusations. Missing validation: \
                                proof format constraints, multi-party confirmation requirement, temporal validity bounds. \
                                Malicious actors can submit fabricated proofs causing unjust slashing. Should require \
                                multiple independent proofs or threshold signatures.",
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

    fn detect_slashing_amount_calculation_inconsistency(&self) -> Vec<SlashingAmbiguityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Penalty amount calculation
            if opcode == 0x02 || opcode == 0x04 { // MUL or DIV
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check if calculating penalty based on stake
                let has_stake_load = window.iter().any(|&b| b == 0x54); // SLOAD
                
                if has_stake_load {
                    // Check for penalty rate consistency
                    let has_constant_rate = window.windows(2).any(|w| w[0] >= 0x60 && w[0] <= 0x7F); // PUSH (constant)
                    
                    // Check for severity-based calculation
                    let has_severity_factor = window.iter().filter(|&&b| matches!(b, 0x02 | 0x04)).count() > 1;
                    
                    // Check for bounds on penalty amount
                    let window_end = (pc + 50).min(self.bytecode.len());
                    let forward_window = &self.bytecode[pc..window_end];
                    let has_max_penalty = forward_window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if !has_constant_rate && has_severity_factor && !has_max_penalty {
                        vulns.push(SlashingAmbiguityVulnerability {
                            pc,
                            vulnerability_type: "SlashingAmountCalculationInconsistency".to_string(),
                            description: format!(
                                "Slashing penalty calculation at PC {} uses dynamic formula without bounds. \
                                Inconsistency risks: (1) penalty varies unpredictably based on network state, \
                                (2) compound severity factors cause excessive slashing, (3) no maximum penalty cap. \
                                Missing safeguards: fixed penalty rates, maximum slash percentage, linear vs exponential \
                                clarity. Validators cannot accurately assess financial risk, deterring participation.",
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
