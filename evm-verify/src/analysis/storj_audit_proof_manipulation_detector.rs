use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorjVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct StorjAuditProofManipulationDetector {
    bytecode: Vec<u8>,
}

impl StorjAuditProofManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<StorjVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unchecked_audit_response());
        vulnerabilities.extend(self.detect_proof_of_retrievability_bypass());
        vulnerabilities.extend(self.detect_node_reputation_manipulation());

        vulnerabilities
    }

    fn detect_unchecked_audit_response(&self) -> Vec<StorjVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // External call (audit request to Storj node)
            if matches!(opcode, 0xF1 | 0xFA) {
                let mut check_pc = pc + 1;
                let mut found_sstore = false;
                let mut has_merkle_verification = false;
                let mut instructions = 0;

                while check_pc < self.bytecode.len() && instructions < 70 {
                    let check_op = self.bytecode[check_pc];
                    
                    if check_op == 0x55 { // SSTORE
                        found_sstore = true;
                    }
                    
                    // Look for Merkle proof verification (multiple KECCAK256 operations)
                    if check_op == 0x20 { // KECCAK256
                        // Check if there are multiple hash operations (Merkle tree verification)
                        let ahead_end = (check_pc + 30).min(self.bytecode.len());
                        let hash_count = self.bytecode[check_pc..ahead_end].iter().filter(|&&b| b == 0x20).count();
                        if hash_count > 1 {
                            has_merkle_verification = true;
                        }
                    }
                    
                    check_pc += 1;
                    instructions += 1;
                    
                    if check_op >= 0x60 && check_op <= 0x7F {
                        check_pc += (check_op - 0x5F) as usize;
                    }
                }

                if found_sstore && !has_merkle_verification {
                    vulns.push(StorjVulnerability {
                        pc,
                        vulnerability_type: "UncheckedAuditResponse".to_string(),
                        description: format!(
                            "Storj audit response at PC {} stored without Merkle proof verification. \
                            Missing validation of: Merkle tree path authenticity, challenge-response correctness, \
                            node's proof-of-possession. Malicious storage nodes can: fake audit responses, \
                            claim file possession without actual storage, pass audits for corrupted/deleted data, \
                            collect payment without providing storage service.",
                            pc
                        ),
                        confidence: 0.88,
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

    fn detect_proof_of_retrievability_bypass(&self) -> Vec<StorjVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for challenge generation (random number for audit)
            if opcode == 0x40 || opcode == 0x44 { // BLOCKHASH or DIFFICULTY
                let window_end = (pc + 50).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check if used for generating audit challenge
                let has_keccak = window.iter().any(|&b| b == 0x20);
                
                if has_keccak {
                    // Check for challenge freshness validation
                    let has_timestamp = window.iter().any(|&b| b == 0x42);
                    
                    // Check for challenge unpredictability (should not use predictable sources)
                    let uses_predictable_source = opcode == 0x44; // DIFFICULTY is predictable
                    
                    if !has_timestamp || uses_predictable_source {
                        vulns.push(StorjVulnerability {
                            pc,
                            vulnerability_type: "ProofOfRetrievabilityBypass".to_string(),
                            description: format!(
                                "Storj audit challenge at PC {} uses weak randomness source. \
                                Vulnerable to: predictable challenge generation, pre-computation of responses, \
                                outsourcing attacks where nodes store only challenges instead of full data. \
                                Missing: high-entropy randomness, challenge freshness validation, response timing bounds. \
                                Enables storage nodes to cheat proof-of-retrievability protocol.",
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

    fn detect_node_reputation_manipulation(&self) -> Vec<StorjVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // SSTORE for reputation/score updates
            if opcode == 0x55 {
                let start = if pc > 60 { pc - 60 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Look for arithmetic operations (reputation calculation)
                let has_arithmetic = window.iter().any(|&b| matches!(b, 0x01 | 0x02 | 0x03 | 0x04)); // ADD, MUL, SUB, DIV
                
                if has_arithmetic {
                    // Check for Sybil resistance (address uniqueness verification)
                    let has_uniqueness_check = window.iter().any(|&b| b == 0x18); // XOR for address comparison
                    
                    // Check for historical validation (SLOAD for previous reputation)
                    let has_history_check = window.iter().any(|&b| b == 0x54); // SLOAD
                    
                    if !has_uniqueness_check && !has_history_check {
                        vulns.push(StorjVulnerability {
                            pc,
                            vulnerability_type: "NodeReputationManipulation".to_string(),
                            description: format!(
                                "Storj node reputation update at PC {} lacks Sybil resistance. \
                                Missing protections: node identity verification, stake-based reputation weighting, \
                                historical performance validation. Attacker can: create multiple fake node identities, \
                                manipulate reputation scores, gain unfair share of storage contracts, \
                                execute Sybil attacks on decentralized storage network.",
                                pc
                            ),
                            confidence: 0.80,
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
