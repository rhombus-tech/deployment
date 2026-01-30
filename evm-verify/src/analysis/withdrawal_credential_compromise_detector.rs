use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalCredentialVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct WithdrawalCredentialCompromiseDetector {
    bytecode: Vec<u8>,
}

impl WithdrawalCredentialCompromiseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<WithdrawalCredentialVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_credential_update_authorization());
        vulnerabilities.extend(self.detect_bls_to_execution_change_vulnerability());
        vulnerabilities.extend(self.detect_credential_rotation_lock());

        vulnerabilities
    }

    fn detect_credential_update_authorization(&self) -> Vec<WithdrawalCredentialVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Withdrawal credential update (SSTORE)
            if opcode == 0x55 {
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check if updating withdrawal address
                let has_address_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_address_data {
                    // Check for authorization mechanism
                    let has_signature = window.iter().any(|&b| b == 0x01); // ECRECOVER
                    let has_caller_check = window.iter().any(|&b| b == 0x33); // CALLER
                    
                    // Check for multi-sig requirement
                    let sig_count = window.iter().filter(|&&b| b == 0x01).count();
                    
                    // Check for timelock
                    let has_timelock = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    if sig_count < 2 && !has_caller_check && !has_timelock {
                        vulns.push(WithdrawalCredentialVulnerability {
                            pc,
                            vulnerability_type: "CredentialUpdateAuthorization".to_string(),
                            description: format!(
                                "Withdrawal credential update at PC {} with insufficient authorization ({} signatures). \
                                Single-key compromise risk: if validator operator key compromised, attacker redirects \
                                all withdrawals to malicious address. Missing protections: multi-sig requirement, \
                                timelock delay, separate withdrawal authority. Should require both consensus layer \
                                signature AND execution layer authorization for changes.",
                                pc, sig_count
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

    fn detect_bls_to_execution_change_vulnerability(&self) -> Vec<WithdrawalCredentialVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // BLS signature verification (credential change authorization)
            if opcode == 0x08 { // bn256Pairing (BLS verification)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for BLS credential data
                let has_bls_pubkey = window.windows(2).any(|w| w[0] == 0x60 && w[1] == 0x30); // PUSH1 48 (BLS pubkey length)
                
                if has_bls_pubkey {
                    // Check for validator index verification
                    let has_index_check = window.iter().any(|&b| matches!(b, 0x14 | 0x10)); // EQ, LT
                    
                    // Check for execution address validation
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward_window = &self.bytecode[pc..window_end];
                    
                    let has_address_validation = forward_window.iter().any(|&b| b == 0x15); // ISZERO (checking non-zero)
                    
                    // Check for replay protection
                    let has_nonce = window.iter().any(|&b| b == 0x54); // SLOAD (nonce check)
                    
                    if !has_index_check && !has_address_validation && !has_nonce {
                        vulns.push(WithdrawalCredentialVulnerability {
                            pc,
                            vulnerability_type: "BLSToExecutionChangeVulnerability".to_string(),
                            description: format!(
                                "BLS-to-execution credential change at PC {} lacks comprehensive validation. \
                                Attack vectors: (1) credential change for wrong validator index (affecting other validators), \
                                (2) setting withdrawal address to zero/burn address, (3) replaying valid credential change \
                                messages. Missing checks: validator index-to-pubkey binding, non-zero address enforcement, \
                                message nonce/uniqueness. Can cause permanent fund loss or credential hijacking.",
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

    fn detect_credential_rotation_lock(&self) -> Vec<WithdrawalCredentialVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Check for credential update tracking
            if opcode == 0x55 { // SSTORE
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Look for last update timestamp
                let has_timestamp_store = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                
                if has_timestamp_store {
                    // Check for rate limiting on credential changes
                    let has_time_check = window.windows(3).any(|w| {
                        w[0] == 0x42 && w[1] == 0x54 && w[2] == 0x03 // TIMESTAMP, SLOAD, SUB (time delta)
                    });
                    
                    let has_min_interval = has_time_check && window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    // Check for maximum rotation count
                    let has_rotation_counter = window.iter().filter(|&&b| b == 0x54).count() > 1;
                    
                    if !has_min_interval && !has_rotation_counter {
                        vulns.push(WithdrawalCredentialVulnerability {
                            pc,
                            vulnerability_type: "CredentialRotationLock".to_string(),
                            description: format!(
                                "Withdrawal credential management at PC {} allows unlimited rapid rotations. \
                                Griefing attack: compromised operator rapidly rotates credentials between addresses, \
                                confusing legitimate owner, making recovery difficult. Missing rate limits: minimum time \
                                between changes, maximum rotations per period, cooldown after suspicious activity. \
                                Should enforce waiting period (e.g., 7 days) to allow dispute resolution.",
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
}
