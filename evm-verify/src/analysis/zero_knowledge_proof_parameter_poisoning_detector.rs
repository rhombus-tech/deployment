use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkParameterVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ZeroKnowledgeProofParameterPoisoningDetector {
    bytecode: Vec<u8>,
}

impl ZeroKnowledgeProofParameterPoisoningDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ZkParameterVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_pairing_with_calldata());
        vulnerabilities.extend(self.detect_unvalidated_verifying_key());
        vulnerabilities.extend(self.detect_public_input_manipulation());
        vulnerabilities.extend(self.detect_zk_proof_verification_with_user_supplied_verifying_keys());

        vulnerabilities
    }

    fn detect_pairing_with_calldata(&self) -> Vec<ZkParameterVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // bn256Pairing precompile (0x08)
            if opcode == 0x60 && pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x08 {
                let window_end = (pc + 80).min(self.bytecode.len());
                let mut has_pairing_call = false;
                let mut has_calldata_input = false;
                
                for check_pc in (pc + 2)..window_end {
                    if self.bytecode[check_pc] == 0xFA || self.bytecode[check_pc] == 0xF1 {
                        has_pairing_call = true;
                        
                        // Check if input comes from CALLDATALOAD
                        let input_start = if check_pc > 60 { check_pc - 60 } else { 0 };
                        has_calldata_input = self.bytecode[input_start..check_pc]
                            .iter().any(|&b| b == 0x35);
                        break;
                    }
                }
                
                if has_pairing_call && has_calldata_input {
                    vulns.push(ZkParameterVulnerability {
                        pc,
                        vulnerability_type: "PairingWithUserInput".to_string(),
                        description: format!(
                            "bn256Pairing at PC {} with user-supplied points. ZK proof verification vulnerable to: \
                            (1) Malicious verifying key injection, (2) Invalid pairing points, (3) Proof forgery with \
                            poisoned parameters. Verifying key MUST be hardcoded or stored in trusted storage. \
                            Never accept verifying key from calldata.",
                            pc
                        ),
                        confidence: 0.90,
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

    fn detect_unvalidated_verifying_key(&self) -> Vec<ZkParameterVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // bn256Pairing (0x08)
            if opcode == 0x60 && pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x08 {
                let window_end = (pc + 100).min(self.bytecode.len());
                let mut has_pairing = false;
                let mut has_hash_check = false;
                
                for check_pc in (pc + 2)..window_end {
                    if self.bytecode[check_pc] == 0xFA {
                        has_pairing = true;
                        
                        // Check for verifying key validation (KECCAK256 comparison)
                        let vk_start = if check_pc > 80 { check_pc - 80 } else { 0 };
                        let vk_window = &self.bytecode[vk_start..check_pc];
                        
                        let has_keccak = vk_window.iter().any(|&b| b == 0x20);
                        let has_eq = vk_window.iter().any(|&b| b == 0x14);
                        has_hash_check = has_keccak && has_eq;
                        break;
                    }
                }
                
                if has_pairing && !has_hash_check {
                    vulns.push(ZkParameterVulnerability {
                        pc,
                        vulnerability_type: "UnvalidatedVerifyingKey".to_string(),
                        description: format!(
                            "ZK pairing at PC {} without verifying key validation. Attacker can: (1) Substitute \
                            verifying key to accept invalid proofs, (2) Bypass proof verification entirely, \
                            (3) Forge proofs for any statement. Validate verifying key: \
                            require(keccak256(vk) == TRUSTED_VK_HASH).",
                            pc
                        ),
                        confidence: 0.85,
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

    fn detect_public_input_manipulation(&self) -> Vec<ZkParameterVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for CALLDATALOAD followed by pairing precompile
            if opcode == 0x35 { // CALLDATALOAD
                let window_end = (pc + 120).min(self.bytecode.len());
                let window = &self.bytecode[(pc + 1)..window_end];
                
                // Check if this calldata used in pairing operation
                let has_pairing = window.windows(2).any(|w| w[0] == 0x60 && w[1] == 0x08);
                
                // Check for public input hashing (binding proof to inputs)
                let has_input_hash = window.iter().any(|&b| b == 0x20); // KECCAK256
                
                if has_pairing && !has_input_hash {
                    vulns.push(ZkParameterVulnerability {
                        pc,
                        vulnerability_type: "UnboundPublicInputs".to_string(),
                        description: format!(
                            "User input at PC {} flows to ZK verification without binding. Public inputs not \
                            cryptographically bound to proof. Attacker can: (1) Reuse valid proof with different \
                            public inputs, (2) Submit proof from one transaction in different context. \
                            Include keccak256(publicInputs) in pairing check.",
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

    fn detect_zk_proof_verification_with_user_supplied_verifying_keys(&self) -> Vec<ZkParameterVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for CALLDATALOAD followed by pairing precompile
            if opcode == 0x35 { // CALLDATALOAD
                let window_end = (pc + 120).min(self.bytecode.len());
                let window = &self.bytecode[(pc + 1)..window_end];
                
                // Check if this calldata used in pairing operation
                let has_pairing = window.windows(2).any(|w| w[0] == 0x60 && w[1] == 0x08);
                
                // Check for verifying key loading from calldata
                let has_vk_load = window.iter().any(|&b| b == 0x54); // SLOAD
                
                if has_pairing && has_vk_load {
                    vulns.push(ZkParameterVulnerability {
                        pc,
                        vulnerability_type: "UserSuppliedVerifyingKey".to_string(),
                        description: format!(
                            "User-supplied verifying key at PC {} used in ZK proof verification. \
                            Enables parameter poisoning attacks. Verifying key MUST be hardcoded or stored in \
                            trusted storage. Never accept verifying key from calldata.",
                            pc
                        ),
                        confidence: 0.95,
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
}
