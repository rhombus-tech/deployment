use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObliviousTransferVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ObliviousTransferSelectiveFailureDetector {
    bytecode: Vec<u8>,
}

impl ObliviousTransferSelectiveFailureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ObliviousTransferVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_choice_bit_leakage());
        vulnerabilities.extend(self.detect_malicious_sender_attack());
        vulnerabilities.extend(self.detect_missing_consistency_check());

        vulnerabilities
    }

    fn detect_choice_bit_leakage(&self) -> Vec<ObliviousTransferVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for choice bit usage in OT protocol
            if opcode == 0x35 { // CALLDATALOAD (reading choice bit)
                let window_end = (pc + 70).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check if choice bit is used in branching
                let has_jumpi = window.iter().any(|&b| b == 0x57); // JUMPI
                
                if has_jumpi {
                    // Check for blinding/masking of choice bit
                    let has_xor_blinding = window.iter().any(|&b| b == 0x18); // XOR
                    let has_hash_blinding = window.iter().any(|&b| b == 0x20); // KECCAK256
                    
                    // Check if leaks through transaction order or gas
                    let start = if pc > 40 { pc - 40 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    let has_timestamp_dep = pre_window.iter().any(|&b| b == 0x42);
                    
                    if !has_xor_blinding && !has_hash_blinding || has_timestamp_dep {
                        vulns.push(ObliviousTransferVulnerability {
                            pc,
                            vulnerability_type: "ChoiceBitLeakage".to_string(),
                            description: format!(
                                "Oblivious Transfer choice bit at PC {} processed without proper blinding. \
                                Vulnerable to leakage through: transaction timing revealing choice, gas consumption \
                                differences, execution path analysis. Missing protections: cryptographic blinding \
                                of choice bit, constant-time processing, indistinguishable execution paths. \
                                Sender can learn receiver's choice, violating OT obliviousness property.",
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

    fn detect_malicious_sender_attack(&self) -> Vec<ObliviousTransferVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // External call receiving OT messages from sender
            if matches!(opcode, 0xF1 | 0xFA) {
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check if storing received messages
                let has_sstore = window.iter().any(|&b| b == 0x55);
                
                if has_sstore {
                    // Check for message consistency validation
                    // Look for: commitment opening, zero-knowledge proof, consistency check
                    let start = if pc > 100 { pc - 100 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_commitment_check = pre_window.iter().any(|&b| b == 0x20); // KECCAK256
                    let has_equality_verification = window.iter().any(|&b| b == 0x14); // EQ
                    
                    // Check for zero-knowledge proof of correct encryption
                    let has_zk_proof = pre_window.iter().any(|&b| b == 0x08); // bn256Pairing
                    
                    if !has_commitment_check || !has_equality_verification && !has_zk_proof {
                        vulns.push(ObliviousTransferVulnerability {
                            pc,
                            vulnerability_type: "MaliciousSenderAttack".to_string(),
                            description: format!(
                                "Oblivious Transfer message reception at PC {} without sender validation. \
                                Missing defenses against malicious sender providing: inconsistent message pairs, \
                                correlated messages revealing choice, invalid encryptions. Malicious sender can: \
                                learn receiver's choice through message correlation, provide useless data on unchosen path, \
                                break OT security by violating message independence. Should enforce commitment to messages \
                                or zero-knowledge proof of correct encryption.",
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

    fn detect_missing_consistency_check(&self) -> Vec<ObliviousTransferVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Decryption/XOR operations (revealing OT result)
            if opcode == 0x18 { // XOR
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check if this is OT message decryption (using choice bit)
                let has_choice = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_external_msg = window.iter().any(|&b| matches!(b, 0xF1 | 0xFA));
                
                if has_choice && has_external_msg {
                    // Check for consistency validation of decrypted result
                    let window_end = (pc + 50).min(self.bytecode.len());
                    let forward_window = &self.bytecode[pc..window_end];
                    
                    // Look for hash check or format validation
                    let has_validation = forward_window.iter().any(|&b| matches!(b, 0x20 | 0x14)); // KECCAK256 or EQ
                    
                    // Check for revert on invalid result
                    let has_revert = forward_window.iter().any(|&b| b == 0xFD);
                    
                    if !has_validation && !has_revert {
                        vulns.push(ObliviousTransferVulnerability {
                            pc,
                            vulnerability_type: "MissingConsistencyCheck".to_string(),
                            description: format!(
                                "Oblivious Transfer result decryption at PC {} without consistency validation. \
                                Accepting potentially malformed or manipulated OT output. Missing checks for: \
                                message format correctness, encryption scheme consistency, chosen message authenticity. \
                                Enables attacks where: malicious sender provides garbage on unchosen index, \
                                encryption is malformed causing incorrect decryption, receiver accepts invalid protocol output. \
                                Should validate decrypted message format and authenticity.",
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
