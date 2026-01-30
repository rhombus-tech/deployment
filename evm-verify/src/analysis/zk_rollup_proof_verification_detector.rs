use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkRollupProofVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ZkRollupProofVerificationDetector {
    bytecode: Vec<u8>,
}

impl ZkRollupProofVerificationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ZkRollupProofVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_proof_verification_bypass());
        vulnerabilities.extend(self.detect_malformed_proof_acceptance());
        vulnerabilities.extend(self.detect_proof_verification_dos());

        vulnerabilities
    }

    fn detect_proof_verification_bypass(&self) -> Vec<ZkRollupProofVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xFA { // STATICCALL (verifier contract)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_proof_data = window.iter().filter(|&&b| b == 0x35).count() >= 2; // CALLDATALOAD
                
                if has_proof_data {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let checks_return_value = forward.iter().any(|&b| b == 0x15); // ISZERO (check success)
                    let reverts_on_failure = forward.iter().any(|&b| b == 0xFD); // REVERT
                    
                    if !checks_return_value || !reverts_on_failure {
                        vulns.push(ZkRollupProofVulnerability {
                            pc,
                            vulnerability_type: "ProofVerificationBypass".to_string(),
                            description: format!(
                                "ZK proof verification at PC {} doesn't properly check verifier return value. Attack: ZK rollup calls verifier contract but doesn't validate \
                                return value, attacker submits invalid proof, verifier returns false, but contract doesn't revert, invalid state transition accepted. Verification \
                                bypass. Example: zkSync/StarkNet verifier call succeeds but returns false, contract continues execution, accepts fraudulent batch. Missing: \
                                require(verifier.verify(proof, publicInputs), 'Proof verification failed'), proper error handling on STATICCALL failure. Should implement: \
                                (bool success, bytes memory result) = verifier.staticcall(proofData), require(success && abi.decode(result, (bool)), 'Invalid proof').",
                                pc
                            ),
                            confidence: 0.92,
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

    fn detect_malformed_proof_acceptance(&self) -> Vec<ZkRollupProofVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x35 { // CALLDATALOAD (proof data)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_verifier_call = window.iter().any(|&b| b == 0xFA); // STATICCALL
                
                if has_verifier_call {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_proof_length_check = pre_window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_proof_format_validation = pre_window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    
                    if !has_proof_length_check {
                        vulns.push(ZkRollupProofVulnerability {
                            pc,
                            vulnerability_type: "MalformedProofAcceptance".to_string(),
                            description: format!(
                                "Proof data loading at PC {} lacks format validation. Attack: ZK rollup accepts proof without validating structure, attacker submits malformed \
                                proof (wrong length, invalid encoding, missing components), causes verifier to behave unexpectedly or accept invalid proof. Missing: proof length \
                                validation (SNARK proofs are fixed size), proof element validation (points on curve), public input count validation. Should implement: \
                                require(proof.length == EXPECTED_PROOF_SIZE, 'Invalid proof length'), validate proof points are on BN254/BLS12-381 curve, verify public inputs \
                                match expected format.",
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

    fn detect_proof_verification_dos(&self) -> Vec<ZkRollupProofVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xFA { // STATICCALL (verifier)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_gas_limit = window.iter().any(|&b| b == 0x5A); // GAS opcode
                
                if !has_gas_limit {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_timeout_protection = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    if !has_timeout_protection {
                        vulns.push(ZkRollupProofVulnerability {
                            pc,
                            vulnerability_type: "ProofVerificationDoS".to_string(),
                            description: format!(
                                "Proof verification call at PC {} lacks gas/time limits. Attack: ZK verifier is expensive operation (200K-2M gas), attacker submits proof that \
                                causes verifier to consume all available gas or run into block gas limit, blocks batch verification, DoS on rollup. Gas griefing. Example: \
                                Groth16 verification costs 200K gas, attacker finds proof that maximizes verifier cost, submits multiple such proofs, congests rollup. Missing: \
                                gas limit on verifier call, batch size limits, verification cost caps. Should implement: verifier.staticcall{{gas: MAX_VERIFICATION_GAS}}(proof), \
                                where MAX_VERIFICATION_GAS = 500K, limit batch size to ensure verification fits in block gas limit.",
                                pc
                            ),
                            confidence: 0.81,
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
