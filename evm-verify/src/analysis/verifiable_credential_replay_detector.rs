use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct VerifiableCredentialReplayDetector {
    bytecode: Vec<u8>,
}

impl VerifiableCredentialReplayDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CredentialVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_missing_nonce_check());
        vulnerabilities.extend(self.detect_missing_expiration());
        vulnerabilities.extend(self.detect_credential_reuse());

        vulnerabilities
    }

    fn detect_missing_nonce_check(&self) -> Vec<CredentialVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // ecrecover signature verification
            if opcode == 0x60 && pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x01 {
                let window_end = (pc + 100).min(self.bytecode.len());
                let mut has_staticcall = false;
                let mut has_nonce_check = false;
                
                for check_pc in (pc + 2)..window_end {
                    if self.bytecode[check_pc] == 0xFA { // STATICCALL to ecrecover
                        has_staticcall = true;
                    }
                    // Check for nonce validation (SLOAD then comparison)
                    if check_pc + 10 < window_end {
                        let window = &self.bytecode[check_pc..(check_pc + 10)];
                        if window.iter().any(|&b| b == 0x54) && window.iter().any(|&b| b == 0x14) {
                            has_nonce_check = true;
                        }
                    }
                }
                
                if has_staticcall && !has_nonce_check {
                    vulns.push(CredentialVulnerability {
                        pc,
                        vulnerability_type: "MissingNonceCheck".to_string(),
                        description: format!(
                            "Signature verification at PC {} without nonce validation. Credential replay attack: \
                            attacker intercepts valid signature and resubmits in different context. Enables: \
                            (1) Double-spending credentials, (2) Multi-use of single-use passes, (3) Authorization replay. \
                            Add: require(nonce == lastNonce[signer] + 1); lastNonce[signer] = nonce;",
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

    fn detect_missing_expiration(&self) -> Vec<CredentialVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // ecrecover precompile call
            if opcode == 0x60 && pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x01 {
                let window_end = (pc + 100).min(self.bytecode.len());
                let mut has_verification = false;
                let mut has_timestamp_check = false;
                
                for check_pc in (pc + 2)..window_end {
                    if self.bytecode[check_pc] == 0xFA {
                        has_verification = true;
                    }
                    // Check for TIMESTAMP comparison
                    if self.bytecode[check_pc] == 0x42 {
                        // Look for comparison (LT or GT)
                        let comp_end = (check_pc + 10).min(window_end);
                        if self.bytecode[check_pc..comp_end].iter().any(|&b| b == 0x10 || b == 0x11) {
                            has_timestamp_check = true;
                        }
                    }
                }
                
                if has_verification && !has_timestamp_check {
                    vulns.push(CredentialVulnerability {
                        pc,
                        vulnerability_type: "MissingExpiration".to_string(),
                        description: format!(
                            "Credential verification at PC {} without expiration check. Credentials valid indefinitely. \
                            Risks: (1) Stolen credentials usable forever, (2) Revoked credentials remain valid, \
                            (3) No time-limited access. Add: require(block.timestamp < expirationTime).",
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

    fn detect_credential_reuse(&self) -> Vec<CredentialVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Signature verification followed by action
            if opcode == 0xFA { // STATICCALL (ecrecover)
                let window_end = (pc + 80).min(self.bytecode.len());
                let mut has_state_change = false;
                let mut has_used_marker = false;
                
                for check_pc in (pc + 1)..window_end {
                    if self.bytecode[check_pc] == 0x55 { // SSTORE
                        has_state_change = true;
                    }
                }
                
                // Check for "signature used" tracking
                let start = if pc > 60 { pc - 60 } else { 0 };
                let has_hash = self.bytecode[start..pc].iter().any(|&b| b == 0x20); // KECCAK256 of sig
                let has_sload_check = self.bytecode[start..window_end].iter().filter(|&&b| b == 0x54).count() >= 2;
                
                if has_hash && has_sload_check {
                    has_used_marker = true;
                }
                
                if has_state_change && !has_used_marker {
                    vulns.push(CredentialVulnerability {
                        pc,
                        vulnerability_type: "CredentialReuse".to_string(),
                        description: format!(
                            "Credential verification at PC {} without replay protection. Same signature can be used \
                            multiple times. Attack: (1) Submit transaction, (2) Resubmit same signature for different action, \
                            (3) Bypass single-use intent. Solution: usedSignatures[keccak256(signature)] = true;",
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
}
