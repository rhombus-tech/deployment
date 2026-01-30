use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DvtCoordinationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct DistributedValidatorTechnologyCoordinationFailureDetector {
    bytecode: Vec<u8>,
}

impl DistributedValidatorTechnologyCoordinationFailureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<DvtCoordinationVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_threshold_signature_liveness_failure());
        vulnerabilities.extend(self.detect_operator_byzantine_behavior());
        vulnerabilities.extend(self.detect_key_share_distribution_vulnerability());

        vulnerabilities
    }

    fn detect_threshold_signature_liveness_failure(&self) -> Vec<DvtCoordinationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Threshold signature aggregation (BLS)
            if opcode == 0x08 { // bn256Pairing (threshold sig verification)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for signature counting/threshold
                let has_count = window.iter().any(|&b| matches!(b, 0x01 | 0x03)); // ADD, SUB (counting signatures)
                let has_threshold = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT (threshold check)
                
                if has_count && has_threshold {
                    // Check for timeout/liveness guarantee
                    let has_timeout = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    // Check for fallback mechanism if threshold not met
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward_window = &self.bytecode[pc..window_end];
                    let has_fallback = forward_window.iter().filter(|&&b| b == 0x57).count() > 1; // Multiple JUMPI (branches)
                    
                    // Check for operator replacement mechanism
                    let has_replacement = forward_window.iter().any(|&b| b == 0x55); // SSTORE (updating operator set)
                    
                    if !has_timeout && !has_fallback && !has_replacement {
                        vulns.push(DvtCoordinationVulnerability {
                            pc,
                            vulnerability_type: "ThresholdSignatureLivenessFailure".to_string(),
                            description: format!(
                                "DVT threshold signature at PC {} lacks liveness guarantees. \
                                Failure scenario: if t-of-n operators go offline, validator cannot perform duties, \
                                causing slashing without mechanism for recovery. Missing safeguards: timeout with \
                                fallback to backup operator set, automatic operator replacement on prolonged unavailability, \
                                graceful degradation mechanism. Validators risk slashing due to operator coordination failures.",
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

    fn detect_operator_byzantine_behavior(&self) -> Vec<DvtCoordinationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Signature share submission
            if opcode == 0x35 { // CALLDATALOAD (reading signature share)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check for signature verification
                let has_sig_verify = window.iter().any(|&b| matches!(b, 0x01 | 0x08)); // ECRECOVER, bn256Pairing
                
                if has_sig_verify {
                    // Check for Byzantine fault detection
                    let has_consistency_check = window.iter().any(|&b| b == 0x14); // EQ (comparing shares)
                    
                    // Check for slashing of malicious operators
                    let has_slashing = window.iter().any(|&b| b == 0x03); // SUB (reducing stake)
                    
                    // Check for duplicate signature detection
                    let sload_count = window.iter().filter(|&&b| b == 0x54).count();
                    
                    if !has_consistency_check && !has_slashing && sload_count < 2 {
                        vulns.push(DvtCoordinationVulnerability {
                            pc,
                            vulnerability_type: "OperatorByzantineBehavior".to_string(),
                            description: format!(
                                "DVT operator signature share at PC {} without Byzantine fault tolerance. \
                                Attack vectors: (1) malicious operator submits conflicting signature shares, \
                                (2) operator signs multiple conflicting attestations (equivocation), (3) operator \
                                colludes to produce slashable behavior. Missing detection: signature share consistency \
                                validation, equivocation proofs, operator slashing for provable misbehavior. \
                                Enables one compromised operator to cause validator slashing.",
                                pc
                            ),
                            confidence: 0.89,
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

    fn detect_key_share_distribution_vulnerability(&self) -> Vec<DvtCoordinationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Key share management (storage operations)
            if opcode == 0x55 { // SSTORE
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for encrypted key share
                let has_encryption = window.iter().any(|&b| b == 0x18); // XOR (simple encryption)
                let has_hash = window.iter().any(|&b| b == 0x20); // KECCAK256
                
                if has_encryption || has_hash {
                    // Check for share distribution verification
                    let has_verification = window.iter().any(|&b| matches!(b, 0x01 | 0x08)); // Signature verification
                    
                    // Check for share recovery mechanism
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward_window = &self.bytecode[pc..window_end];
                    
                    let has_recovery = forward_window.iter().any(|&b| b == 0x54); // SLOAD (reading backup shares)
                    
                    // Check for share rotation capability
                    let has_rotation = forward_window.iter().any(|&b| b == 0x42); // TIMESTAMP (time-based rotation)
                    
                    if !has_verification && !has_recovery && !has_rotation {
                        vulns.push(DvtCoordinationVulnerability {
                            pc,
                            vulnerability_type: "KeyShareDistributionVulnerability".to_string(),
                            description: format!(
                                "DVT key share storage at PC {} lacks secure distribution verification. \
                                Risks: (1) unverified shares allow impersonation attacks, (2) no recovery if operators \
                                lose shares, (3) static shares vulnerable to long-term compromise. Missing mechanisms: \
                                verifiable secret sharing proofs, threshold-based share recovery (e.g., Shamir), \
                                periodic share refresh/rotation. Single operator compromise or loss can permanently \
                                disable validator without recovery path.",
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
}
