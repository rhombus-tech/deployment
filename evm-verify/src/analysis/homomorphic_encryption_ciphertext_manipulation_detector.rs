use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomomorphicVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct HomomorphicEncryptionCiphertextManipulationDetector {
    bytecode: Vec<u8>,
}

impl HomomorphicEncryptionCiphertextManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<HomomorphicVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_arithmetic_on_calldata());
        vulnerabilities.extend(self.detect_unvalidated_ciphertext_storage());
        vulnerabilities.extend(self.detect_result_without_range_proof());

        vulnerabilities
    }

    fn detect_arithmetic_on_calldata(&self) -> Vec<HomomorphicVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // CALLDATALOAD (user input)
            if opcode == 0x35 {
                let window_end = (pc + 60).min(self.bytecode.len());
                let window = &self.bytecode[(pc + 1)..window_end];
                
                // Check for arithmetic operations on loaded data (ADD, MUL for homomorphic ops)
                let has_arithmetic = window.iter().any(|&b| b == 0x01 || b == 0x02); // ADD or MUL
                
                // Check for validation (pairing check or modexp)
                let has_validation = window.windows(2).any(|w| {
                    w[0] == 0x60 && (w[1] == 0x05 || w[1] == 0x08) // modexp or pairing
                });
                
                if has_arithmetic && !has_validation {
                    vulns.push(HomomorphicVulnerability {
                        pc,
                        vulnerability_type: "UnvalidatedHomomorphicOp".to_string(),
                        description: format!(
                            "Arithmetic on user input at PC {} without ciphertext validation. In homomorphic \
                            encryption schemes (Paillier, ElGamal, BFV), ciphertexts must be validated before \
                            operations. Attacker can submit: (1) Invalid group elements, (2) Malformed ciphertexts, \
                            (3) Values outside valid range. Validate ciphertexts are in correct group/field.",
                            pc
                        ),
                        confidence: 0.70,
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

    fn detect_unvalidated_ciphertext_storage(&self) -> Vec<HomomorphicVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // SSTORE (storing ciphertext)
            if opcode == 0x55 {
                let start = if pc > 80 { pc - 80 } else { 0 };
                
                // Check if stored value comes from calldata
                let has_calldata = self.bytecode[start..pc].iter().any(|&b| b == 0x35);
                
                // Check for validation before storage
                let has_modexp = self.bytecode[start..pc].windows(2).any(|w| w[0] == 0x60 && w[1] == 0x05);
                let has_pairing = self.bytecode[start..pc].windows(2).any(|w| w[0] == 0x60 && w[1] == 0x08);
                
                if has_calldata && !has_modexp && !has_pairing {
                    vulns.push(HomomorphicVulnerability {
                        pc,
                        vulnerability_type: "UnvalidatedCiphertextStorage".to_string(),
                        description: format!(
                            "User-supplied ciphertext stored at PC {} without validation. Storing invalid \
                            ciphertexts leads to: (1) Incorrect homomorphic computation results, (2) Decryption \
                            failures, (3) Privacy leakage through malformed ciphertexts. Verify ciphertext \
                            well-formedness before accepting.",
                            pc
                        ),
                        confidence: 0.75,
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

    fn detect_result_without_range_proof(&self) -> Vec<HomomorphicVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // ADD or MUL operations (homomorphic addition/multiplication)
            if opcode == 0x01 || opcode == 0x02 {
                let window_end = (pc + 100).min(self.bytecode.len());
                let mut has_sstore = false;
                let mut has_range_proof = false;
                
                // Check if result is stored
                for check_pc in (pc + 1)..window_end {
                    if self.bytecode[check_pc] == 0x55 {
                        has_sstore = true;
                    }
                    // Check for pairing (ZK range proof verification)
                    if self.bytecode[check_pc] == 0x60 && check_pc + 1 < window_end && self.bytecode[check_pc + 1] == 0x08 {
                        has_range_proof = true;
                    }
                }
                
                if has_sstore && !has_range_proof {
                    vulns.push(HomomorphicVulnerability {
                        pc,
                        vulnerability_type: "ResultWithoutRangeProof".to_string(),
                        description: format!(
                            "Homomorphic operation result at PC {} stored without range proof. Encrypted computation \
                            results must include range proofs to prevent: (1) Overflow attacks, (2) Result manipulation, \
                            (3) Computation of invalid values. Require ZK range proof with each homomorphic result.",
                            pc
                        ),
                        confidence: 0.65,
                    });
                    break;
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
