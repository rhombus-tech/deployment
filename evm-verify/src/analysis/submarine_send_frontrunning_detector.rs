use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmarineSendVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct SubmarineSendFrontrunningDetector {
    bytecode: Vec<u8>,
}

impl SubmarineSendFrontrunningDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SubmarineSendVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_commit_reveal_bypass());
        vulnerabilities.extend(self.detect_witness_encryption_weakness());
        vulnerabilities.extend(self.detect_unlock_frontrunning());

        vulnerabilities
    }

    fn detect_commit_reveal_bypass(&self) -> Vec<SubmarineSendVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for commit phase (KECCAK256 of commitment + SSTORE)
            if opcode == 0x20 { // KECCAK256
                let window_end = (pc + 50).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_sstore = window.iter().any(|&b| b == 0x55);
                
                if has_sstore {
                    // Check for reveal phase validation
                    // Look for: timestamp delay enforcement, nonce/counter tracking
                    let start = if pc > 100 { pc - 100 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_timestamp_check = pre_window.iter().any(|&b| b == 0x42);
                    let has_counter = pre_window.windows(2).any(|w| {
                        w[0] == 0x54 && w[1] == 0x01 // SLOAD followed by ADD (counter increment)
                    });
                    
                    if !has_timestamp_check && !has_counter {
                        vulns.push(SubmarineSendVulnerability {
                            pc,
                            vulnerability_type: "CommitRevealBypass".to_string(),
                            description: format!(
                                "Submarine send commit at PC {} lacks proper reveal delay enforcement. \
                                Missing protections: minimum time between commit and reveal, sequential \
                                commitment ordering, replay prevention. Attacker can: bypass hiding period \
                                by immediate reveal, frontrun other commits with knowledge of committed value, \
                                extract MEV from submarine transactions.",
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

    fn detect_witness_encryption_weakness(&self) -> Vec<SubmarineSendVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for XOR encryption patterns (witness encryption for submarine sends)
            if opcode == 0x18 { // XOR
                let window_end = (pc + 60).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check if XOR is used with KECCAK256 (deriving encryption key)
                let start = if pc > 40 { pc - 40 } else { 0 };
                let pre_window = &self.bytecode[start..pc];
                
                let has_keccak_key = pre_window.iter().any(|&b| b == 0x20);
                
                if has_keccak_key {
                    // Check for weak key derivation or missing salt
                    let has_timestamp_salt = pre_window.iter().any(|&b| b == 0x42);
                    let has_blockhash_salt = pre_window.iter().any(|&b| b == 0x40);
                    
                    // Check if encrypted value is stored or emitted
                    let has_storage_or_event = window.iter().any(|&b| {
                        matches!(b, 0x55 | 0xA0 | 0xA1 | 0xA2 | 0xA3 | 0xA4) // SSTORE or LOGx
                    });
                    
                    if has_storage_or_event && !has_timestamp_salt && !has_blockhash_salt {
                        vulns.push(SubmarineSendVulnerability {
                            pc,
                            vulnerability_type: "WitnessEncryptionWeakness".to_string(),
                            description: format!(
                                "Submarine send encryption at PC {} uses weak key derivation. \
                                Vulnerable to: deterministic key prediction, brute-force attacks on small \
                                keyspace, known-plaintext attacks if pattern is predictable. Missing: \
                                timestamp/blockhash salt, sufficient entropy, forward secrecy. Encrypted \
                                submarine transactions can be decrypted before reveal.",
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

    fn detect_unlock_frontrunning(&self) -> Vec<SubmarineSendVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for unlock/reveal transaction that processes submarine send
            if opcode == 0x35 { // CALLDATALOAD (reading witness/key from calldata)
                let window_end = (pc + 50).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check for value transfer after unlock
                let has_call = window.iter().any(|&b| matches!(b, 0xF1 | 0xF0)); // CALL, CREATE
                
                if has_call {
                    // Check for frontrun protection
                    let start = if pc > 60 { pc - 60 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    // Look for sender validation
                    let has_caller_check = pre_window.iter().any(|&b| b == 0x33); // CALLER
                    
                    // Look for commit-time validation
                    let has_commit_validation = pre_window.windows(3).any(|w| {
                        w[0] == 0x54 && w[1] == 0x14 // SLOAD + EQ (checking commitment)
                    });
                    
                    if !has_caller_check && !has_commit_validation {
                        vulns.push(SubmarineSendVulnerability {
                            pc,
                            vulnerability_type: "UnlockFrontrunning".to_string(),
                            description: format!(
                                "Submarine send unlock at PC {} is frontrunnable. No protection against: \
                                mempool monitoring of reveal transaction, extracting witness data from calldata, \
                                frontrunning with stolen witness to claim value. MEV bots can: observe unlock \
                                tx in mempool, copy witness encryption key, submit competing tx with higher gas, \
                                steal submarine send funds.",
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
}
