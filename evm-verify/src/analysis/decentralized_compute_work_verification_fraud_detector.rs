use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeVerificationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct DecentralizedComputeWorkVerificationFraudDetector {
    bytecode: Vec<u8>,
}

impl DecentralizedComputeWorkVerificationFraudDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ComputeVerificationVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unverified_computation_result());
        vulnerabilities.extend(self.detect_work_proof_replay());
        vulnerabilities.extend(self.detect_computation_correctness_bypass());

        vulnerabilities
    }

    fn detect_unverified_computation_result(&self) -> Vec<ComputeVerificationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x35 { // CALLDATALOAD (computation result submission)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_payment = window.iter().any(|&b| matches!(b, 0xF1 | 0x55)); // CALL or SSTORE (payment/storage)
                
                if has_payment {
                    let has_zk_proof = window.iter().any(|&b| b == 0x08); // bn256Pairing (ZK verification)
                    let has_replicated_compute = window.iter().filter(|&&b| matches!(b, 0xFA | 0xF1)).count() >= 2;
                    let has_fraud_proof_period = window.iter().any(|&b| b == 0x43); // NUMBER (challenge window)
                    
                    if !has_zk_proof && !has_replicated_compute && !has_fraud_proof_period {
                        vulns.push(ComputeVerificationVulnerability {
                            pc,
                            vulnerability_type: "UnverifiedComputationResult".to_string(),
                            description: format!(
                                "Computation result at PC {} accepted without verification. Worker can submit arbitrary results \
                                and receive payment. Missing: ZK-SNARK proving correct execution, redundant computation with \
                                consensus, optimistic verification with fraud proofs. No mechanism ensures computation was performed \
                                honestly. Enables result fabrication without detection.",
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

    fn detect_work_proof_replay(&self) -> Vec<ComputeVerificationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (work proof hash)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_proof_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_proof_data {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_nonce = window.iter().any(|&b| b == 0x43); // NUMBER
                    let has_timestamp = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let has_uniqueness_check = forward.iter().any(|&b| b == 0x54); // SLOAD (checking used proofs)
                    
                    if !has_nonce && !has_timestamp && !has_uniqueness_check {
                        vulns.push(ComputeVerificationVulnerability {
                            pc,
                            vulnerability_type: "WorkProofReplay".to_string(),
                            description: format!(
                                "Work proof at PC {} reusable across multiple submissions. Attack: worker submits valid proof once, \
                                replays same proof for different jobs to claim multiple payments. Missing: job-specific nonce, \
                                timestamp freshness requirement, proof uniqueness tracking. Single computation can be claimed as \
                                multiple completed jobs.",
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

    fn detect_computation_correctness_bypass(&self) -> Vec<ComputeVerificationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (storing computation result)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_result_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_result_data {
                    let has_input_hash = window.iter().any(|&b| b == 0x20); // KECCAK256 (input verification)
                    let has_determinism_check = window.iter().filter(|&&b| b == 0x14).count() >= 2; // Multiple EQ
                    let has_stake_slashing = window.iter().any(|&b| b == 0x03); // SUB (penalty)
                    
                    if !has_input_hash || !has_determinism_check || !has_stake_slashing {
                        vulns.push(ComputeVerificationVulnerability {
                            pc,
                            vulnerability_type: "ComputationCorrectnessBypass".to_string(),
                            description: format!(
                                "Result storage at PC {} without correctness guarantees. For deterministic computation, multiple \
                                workers should produce identical results. Missing: input commitment verification, result consensus \
                                among workers, slashing for incorrect results. Worker can submit wrong computation without penalty. \
                                Requires stake and comparison with other workers or verifiable computation proof.",
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
