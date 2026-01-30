use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageAvailabilityVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct DistributedStorageAvailabilityAttackDetector {
    bytecode: Vec<u8>,
}

impl DistributedStorageAvailabilityAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<StorageAvailabilityVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_insufficient_redundancy());
        vulnerabilities.extend(self.detect_data_withholding_attack());
        vulnerabilities.extend(self.detect_erasure_coding_parameter_manipulation());

        vulnerabilities
    }

    fn detect_insufficient_redundancy(&self) -> Vec<StorageAvailabilityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (storing data reference)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_chunk_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_replication = window.iter().any(|&b| b == 0x02); // MUL (replication factor)
                
                if has_chunk_data {
                    let has_minimum_replicas = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let replica_count = window.iter().filter(|&&b| matches!(b, 0xF1 | 0xFA)).count();
                    
                    if !has_minimum_replicas || replica_count < 3 {
                        vulns.push(StorageAvailabilityVulnerability {
                            pc,
                            vulnerability_type: "InsufficientRedundancy".to_string(),
                            description: format!(
                                "Data storage at PC {} with inadequate redundancy (detected {} replicas). Single node failure \
                                causes data loss. Attack: storage provider goes offline, data becomes unavailable. Missing: \
                                minimum replication factor (≥3), geographic distribution requirement, node diversity validation. \
                                Should use erasure coding with k-of-n threshold for resilience.",
                                pc, replica_count
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

    fn detect_data_withholding_attack(&self) -> Vec<StorageAvailabilityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xFA | 0xF1) { // Data retrieval call
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_data_request = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_data_request {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_availability_proof = forward.iter().any(|&b| b == 0x20); // KECCAK256 (proof hash)
                    let has_timeout_fallback = forward.iter().filter(|&&b| b == 0x57).count() >= 2; // Multiple JUMPI
                    let has_slash_mechanism = forward.iter().any(|&b| b == 0x03); // SUB (slashing)
                    
                    if !has_availability_proof || !has_timeout_fallback || !has_slash_mechanism {
                        vulns.push(StorageAvailabilityVulnerability {
                            pc,
                            vulnerability_type: "DataWithholdingAttack".to_string(),
                            description: format!(
                                "Data retrieval at PC {} without availability enforcement. Malicious storage provider withholds \
                                data despite claiming storage. Attack: accept payment for storage, refuse retrieval requests. \
                                Missing: data availability sampling proofs, timeout with fallback providers, economic penalty for \
                                withholding. Should use random challenge-response with slashing.",
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

    fn detect_erasure_coding_parameter_manipulation(&self) -> Vec<StorageAvailabilityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x04 || opcode == 0x02 { // DIV, MUL (erasure coding k/n parameters)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_chunk_count = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_chunk_count {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_ratio_validation = forward.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    let has_minimum_k = window.iter().any(|&b| matches!(b, 0x10 | 0x11));
                    
                    if !has_ratio_validation || !has_minimum_k {
                        vulns.push(StorageAvailabilityVulnerability {
                            pc,
                            vulnerability_type: "ErasureCodingParameterManipulation".to_string(),
                            description: format!(
                                "Erasure coding parameters at PC {} without bounds validation. Attacker sets k too close to n, \
                                reducing fault tolerance. Example: k=99, n=100 means single chunk loss destroys data. Should enforce \
                                k ≤ 0.7*n for reasonable redundancy. Missing: k/n ratio validation, minimum k requirement, maximum \
                                n limit. Weak parameters enable data loss from minimal node failures.",
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
