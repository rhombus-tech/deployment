use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AztecNoirVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct AztecNoirCircuitConstraintBypassDetector {
    bytecode: Vec<u8>,
}

impl AztecNoirCircuitConstraintBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<AztecNoirVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unconstrained_witness_assignment());
        vulnerabilities.extend(self.detect_proof_malleability());
        vulnerabilities.extend(self.detect_public_input_manipulation());

        vulnerabilities
    }

    fn detect_unconstrained_witness_assignment(&self) -> Vec<AztecNoirVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xFA { // STATICCALL (proof verifier)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_proof_data = window.iter().filter(|&&b| b == 0x35).count() >= 3; // CALLDATALOAD
                
                if has_proof_data {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_constraint_validation = window.iter().filter(|&&b| b == 0x20).count() >= 4; // Multiple hashes
                    let checks_witness_bounds = forward.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 3;
                    
                    if !checks_witness_bounds {
                        vulns.push(AztecNoirVulnerability {
                            pc,
                            vulnerability_type: "UnconstrainedWitnessAssignment".to_string(),
                            description: format!(
                                "Noir circuit verification at PC {} may allow unconstrained witness values. Attack: Noir compiles to ACIR (Abstract Circuit Intermediate \
                                Representation), verifier checks constraints but if witness assignments not fully constrained, prover can assign arbitrary values to unconstrained \
                                wires. Example: circuit has witness `w` used in output but no constraint on `w` itself, prover sets `w = malicious_value`, passes verification. \
                                Common in: intermediate variables not connected to public inputs/outputs, unused circuit branches, witness generation bugs. Real exploit: prover \
                                claims balance = 1000 ETH by setting unconstrained witness, circuit verifies because constraint system doesn't enforce witness validity. Missing: \
                                constraint completeness analysis, all witnesses transitively constrained by public inputs, dead code elimination in circuit. Should verify: every \
                                witness reachable from public inputs via constraints, no degrees of freedom in witness assignment.",
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

    fn detect_proof_malleability(&self) -> Vec<AztecNoirVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (proof validation result)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_proof_verification = window.iter().any(|&b| b == 0xFA); // STATICCALL
                let has_proof_uniqueness_check = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                
                if has_proof_verification {
                    let has_nullifier_tracking = window.iter().filter(|&&b| b == 0x55).count() >= 2;
                    let has_commitment_binding = window.iter().filter(|&&b| b == 0x20).count() >= 4;
                    
                    if !has_nullifier_tracking {
                        vulns.push(AztecNoirVulnerability {
                            pc,
                            vulnerability_type: "ProofMalleability".to_string(),
                            description: format!(
                                "Aztec proof verification at PC {} vulnerable to malleability. Attack: same statement can have multiple valid proofs, attacker generates \
                                different proof for same computation, replays transaction with malleable proof. In PLONK/Groth16: proof consists of group elements, if verifier \
                                doesn't bind proof to specific commitment, attacker can modify proof elements while maintaining validity. Example: proof P verifies statement S, \
                                attacker creates P' also verifying S, submits P' to bypass replay protection based on proof hash. Used for: double-spending (prove same nullifier \
                                twice with different proofs), replay attacks, bypassing nonce systems. Missing: proof commitment binding, unique proof representation, nullifier \
                                derived from proof. Should implement: include proof hash in nullifier computation, or use deterministic proof generation, or verify proof + \
                                statement binding.",
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

    fn detect_public_input_manipulation(&self) -> Vec<AztecNoirVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x35 { // CALLDATALOAD (public inputs)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_verifier_call = window.iter().any(|&b| b == 0xFA); // STATICCALL
                
                if has_verifier_call {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let validates_public_input_format = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    let checks_input_commitment = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    
                    if !validates_public_input_format {
                        vulns.push(AztecNoirVulnerability {
                            pc,
                            vulnerability_type: "PublicInputManipulation".to_string(),
                            description: format!(
                                "Public input loading at PC {} lacks validation before proof verification. Attack: Noir circuits take public inputs (visible to verifier) and \
                                private inputs (witnesses), verifier must validate public inputs before checking proof. If contract doesn't validate public input format/bounds, \
                                attacker provides malicious public inputs causing: (1) verifier reads out-of-bounds memory, (2) field overflow in verification equation, (3) \
                                type confusion. Example: circuit expects public input in range [0, 2^253], attacker provides 2^254, causes field arithmetic overflow, breaks \
                                soundness. Or: public input array length unchecked, attacker provides wrong length, verifier behavior undefined. Missing: public input range checks, \
                                array length validation, type validation. Should enforce: validate all public inputs before verification, check field element range, verify array \
                                lengths match circuit spec.",
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
}
