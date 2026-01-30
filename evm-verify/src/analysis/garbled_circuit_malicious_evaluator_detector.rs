use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GarbledCircuitVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct GarbledCircuitMaliciousEvaluatorDetector {
    bytecode: Vec<u8>,
}

impl GarbledCircuitMaliciousEvaluatorDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<GarbledCircuitVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_missing_output_verification());
        vulnerabilities.extend(self.detect_selective_failure_attack());
        vulnerabilities.extend(self.detect_label_malleability());

        vulnerabilities
    }

    fn detect_missing_output_verification(&self) -> Vec<GarbledCircuitVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // External call receiving garbled circuit output
            if matches!(opcode, 0xF1 | 0xFA) {
                let window_end = (pc + 70).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check for subsequent storage of result
                let has_sstore = window.iter().any(|&b| b == 0x55);
                
                if has_sstore {
                    // Check for output commitment verification
                    let has_hash_check = window.iter().any(|&b| b == 0x20); // KECCAK256
                    let has_equality_check = window.iter().any(|&b| b == 0x14); // EQ
                    
                    // Check for zero-knowledge proof verification
                    let start = if pc > 50 { pc - 50 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    let has_zk_verify = pre_window.iter().any(|&b| b == 0x08); // bn256Pairing precompile
                    
                    if !has_hash_check || !has_equality_check && !has_zk_verify {
                        vulns.push(GarbledCircuitVulnerability {
                            pc,
                            vulnerability_type: "MissingOutputVerification".to_string(),
                            description: format!(
                                "Garbled circuit output at PC {} accepted without cryptographic verification. \
                                Missing validation of: output commitment correctness, evaluator's computation honesty, \
                                circuit garbling authenticity. Malicious evaluator can: provide arbitrary false outputs, \
                                selectively evaluate circuit incorrectly, violate privacy guarantees by learning inputs. \
                                Should verify output against committed garbled tables or use verifiable computation.",
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

    fn detect_selective_failure_attack(&self) -> Vec<GarbledCircuitVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Check for circuit evaluation call with error handling
            if matches!(opcode, 0xF1 | 0xFA) {
                let window_end = (pc + 60).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check if return value is checked
                let has_return_check = window.iter().any(|&b| matches!(b, 0x15 | 0x16)); // ISZERO, NOT
                
                if has_return_check {
                    // Check for abort/retry mechanism on failure
                    let has_revert = window.iter().any(|&b| b == 0xFD);
                    
                    // Check for alternative execution path
                    let has_jumpi = window.iter().any(|&b| b == 0x57);
                    
                    // Missing commitment to handling all cases
                    if !has_revert && has_jumpi {
                        vulns.push(GarbledCircuitVulnerability {
                            pc,
                            vulnerability_type: "SelectiveFailureAttack".to_string(),
                            description: format!(
                                "Garbled circuit evaluation at PC {} vulnerable to selective failure. \
                                Evaluator can: abort evaluation on unfavorable inputs, learn input information \
                                from selective failures, force re-garbling to extract multiple label sets. \
                                Missing protections: abort penalty mechanism, commitment to completion regardless \
                                of input, fairness guarantees preventing early abort. Enables input-dependent \
                                denial-of-service and privacy violation.",
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

    fn detect_label_malleability(&self) -> Vec<GarbledCircuitVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // XOR operations on circuit labels
            if opcode == 0x18 { // XOR
                let start = if pc > 60 { pc - 60 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check if operating on external data (labels from garbler)
                let has_calldata = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_calldata {
                    // Check for label authentication (MAC or signature)
                    let has_mac = window.iter().any(|&b| b == 0x20); // KECCAK256 for MAC
                    let has_signature = window.iter().any(|&b| b == 0x01); // ECRECOVER
                    
                    // Check for point-and-permute protection
                    let window_end = (pc + 40).min(self.bytecode.len());
                    let forward_window = &self.bytecode[pc..window_end];
                    let has_bit_check = forward_window.iter().any(|&b| matches!(b, 0x1A | 0x1B)); // BYTE, SHL
                    
                    if !has_mac && !has_signature && !has_bit_check {
                        vulns.push(GarbledCircuitVulnerability {
                            pc,
                            vulnerability_type: "LabelMalleability".to_string(),
                            description: format!(
                                "Garbled circuit label processing at PC {} without authentication. \
                                Vulnerable to: wire label manipulation by malicious evaluator, XOR-based attacks \
                                on Free-XOR garbling, label forgery to force specific outputs. Missing protections: \
                                authenticated encryption of garbled tables, point-and-permute technique, label MACs. \
                                Attacker can: flip label bits to alter computation, forge labels for specific wires, \
                                break privacy by testing manipulated labels.",
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
