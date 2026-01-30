use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct KeyRotationReplayAttackDetector {
    bytecode: Vec<u8>,
}

impl KeyRotationReplayAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<KeyRotationVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect ecrecover without nonce in signed message
        vulnerabilities.extend(self.detect_nonceless_signatures());
        
        // Detect signer updates without signature invalidation
        vulnerabilities.extend(self.detect_rotation_without_invalidation());
        
        // Detect signature verification without timestamp checks
        vulnerabilities.extend(self.detect_timeless_signatures());

        vulnerabilities
    }

    fn detect_nonceless_signatures(&self) -> Vec<KeyRotationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for ecrecover precompile
            if opcode == 0x60 && pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x01 {
                let window_end = (pc + 100).min(self.bytecode.len());
                let mut found_ecrecover = false;
                let mut has_nonce_in_hash = false;
                
                // Find STATICCALL to ecrecover
                for check_pc in (pc + 2)..window_end {
                    if self.bytecode[check_pc] == 0xFA {
                        found_ecrecover = true;
                        
                        // Check if message hash includes nonce (SLOAD before KECCAK256)
                        let hash_start = if check_pc > 80 { check_pc - 80 } else { 0 };
                        let hash_window = &self.bytecode[hash_start..check_pc];
                        
                        // Look for SLOAD (loading nonce) near KECCAK256 (hashing message)
                        let has_sload = hash_window.iter().any(|&b| b == 0x54);
                        let has_keccak = hash_window.iter().any(|&b| b == 0x20);
                        has_nonce_in_hash = has_sload && has_keccak;
                        break;
                    }
                }
                
                if found_ecrecover && !has_nonce_in_hash {
                    vulns.push(KeyRotationVulnerability {
                        pc,
                        vulnerability_type: "NoncelessSignature".to_string(),
                        description: format!(
                            "Signature verification at PC {} without nonce in message. After key rotation, \
                            attacker can replay old signatures signed with previous key. Without nonce/sequence \
                            number in signed data, same signature valid indefinitely. Include incrementing nonce \
                            in message hash: keccak256(abi.encode(data, nonce, address(this), chainId)).",
                            pc
                        ),
                        confidence: 0.80,
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

    fn detect_rotation_without_invalidation(&self) -> Vec<KeyRotationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut has_signer_update = false;
        let mut has_signature_clear = false;

        // First pass: detect signer storage updates (key rotation)
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // SSTORE operation that might update signer address
            if opcode == 0x55 {
                // Check if preceded by CALLER (msg.sender becoming new signer)
                let start = if pc > 30 { pc - 30 } else { 0 };
                if self.bytecode[start..pc].iter().any(|&b| b == 0x33) {
                    has_signer_update = true;
                    break;
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        if !has_signer_update {
            return vulns;
        }

        // Second pass: check for signature/nonce clearing after rotation
        pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for PUSH 0 followed by SSTORE (clearing storage)
            if opcode == 0x60 && pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x00 {
                let window_end = (pc + 15).min(self.bytecode.len());
                if self.bytecode[(pc + 2)..window_end].iter().any(|&b| b == 0x55) {
                    has_signature_clear = true;
                    break;
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        if has_signer_update && !has_signature_clear {
            vulns.push(KeyRotationVulnerability {
                pc: 0,
                vulnerability_type: "RotationWithoutInvalidation".to_string(),
                description: "Signer rotation without invalidating existing signatures/nonces. Old signatures \
                    remain valid after key rotation. Attacker with old key can: (1) Replay previously \
                    authorized transactions, (2) Execute stale proposals, (3) Bypass new signer's control. \
                    Clear all pending signatures and increment global nonce on rotation.".to_string(),
                confidence: 0.75,
            });
        }

        vulns
    }

    fn detect_timeless_signatures(&self) -> Vec<KeyRotationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for ecrecover
            if opcode == 0x60 && pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x01 {
                let window_end = (pc + 100).min(self.bytecode.len());
                let mut found_ecrecover = false;
                let mut has_timestamp_in_sig = false;
                
                for check_pc in (pc + 2)..window_end {
                    if self.bytecode[check_pc] == 0xFA {
                        found_ecrecover = true;
                        
                        // Check if TIMESTAMP or NUMBER included in message hash
                        let hash_start = if check_pc > 80 { check_pc - 80 } else { 0 };
                        let hash_window = &self.bytecode[hash_start..check_pc];
                        
                        let has_timestamp = hash_window.iter().any(|&b| b == 0x42 || b == 0x43);
                        let has_keccak = hash_window.iter().any(|&b| b == 0x20);
                        has_timestamp_in_sig = has_timestamp && has_keccak;
                        break;
                    }
                }
                
                if found_ecrecover && !has_timestamp_in_sig {
                    vulns.push(KeyRotationVulnerability {
                        pc,
                        vulnerability_type: "TimelessSignature".to_string(),
                        description: format!(
                            "Signature at PC {} without timestamp/deadline. Signatures valid indefinitely. \
                            After key rotation or compromise, old signatures can be replayed forever. \
                            Include deadline in signed message: require(block.timestamp < signedDeadline). \
                            Or include block.number to make signatures expire automatically.",
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
}
