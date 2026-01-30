use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TrustedExecutionEnvironmentSideChannelDetector {
    bytecode: Vec<u8>,
}

impl TrustedExecutionEnvironmentSideChannelDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<TeeVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_attestation_replay());
        vulnerabilities.extend(self.detect_side_channel_leakage());
        vulnerabilities.extend(self.detect_rollback_attack_vulnerability());

        vulnerabilities
    }

    fn detect_attestation_replay(&self) -> Vec<TeeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Signature verification (ECRECOVER for TEE attestation)
            if opcode == 0x60 && pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x01 {
                let window_end = (pc + 70).min(self.bytecode.len());
                let has_ecrecover = self.bytecode[pc..window_end].iter().any(|&b| b == 0xFA);
                
                if has_ecrecover {
                    // Check for nonce/timestamp validation
                    let has_nonce = self.bytecode[pc..window_end].iter().any(|&b| b == 0x54); // SLOAD for nonce
                    let has_timestamp = self.bytecode[pc..window_end].iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    if !has_nonce && !has_timestamp {
                        vulns.push(TeeVulnerability {
                            pc,
                            vulnerability_type: "AttestationReplay".to_string(),
                            description: format!(
                                "TEE attestation verification at PC {} without replay protection. \
                                Missing validation of: attestation freshness, nonce uniqueness, timestamp bounds. \
                                Attacker can: replay old valid attestations, reuse compromised but previously-valid \
                                TEE signatures, bypass attestation expiry. Should enforce nonce-based or time-bounded \
                                attestation with cryptographic freshness guarantees.",
                                pc
                            ),
                            confidence: 0.89,
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

    fn detect_side_channel_leakage(&self) -> Vec<TeeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Secret-dependent branching (JUMPI with secret data)
            if opcode == 0x57 { // JUMPI
                let start = if pc > 50 { pc - 50 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check if condition depends on TEE-provided secret
                // Look for CALLDATALOAD (secret from TEE) followed by comparison
                let has_secret_load = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_comparison = window.iter().any(|&b| matches!(b, 0x14 | 0x10 | 0x11)); // EQ, LT, GT
                
                if has_secret_load && has_comparison {
                    // Check for constant-time operation markers
                    let has_constant_time_ops = window.iter().all(|&b| {
                        // Constant-time ops: arithmetic, bitwise (no branching)
                        !matches!(b, 0x56 | 0x57 | 0x58) // Not JUMP, JUMPI, PC
                    });
                    
                    if !has_constant_time_ops {
                        vulns.push(TeeVulnerability {
                            pc,
                            vulnerability_type: "SideChannelLeakage".to_string(),
                            description: format!(
                                "TEE secret processing at PC {} uses secret-dependent branching. \
                                Vulnerable to timing side-channels through: variable execution paths based on secrets, \
                                gas consumption differences revealing secret bits, transaction ordering exposing \
                                secret-dependent state. Attacker monitoring on-chain timing can: extract TEE secrets \
                                via timing analysis, correlate gas usage with secret values, break confidentiality \
                                guarantees. Should use constant-time operations for secret processing.",
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

    fn detect_rollback_attack_vulnerability(&self) -> Vec<TeeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // SSTORE operations storing TEE state
            if opcode == 0x55 {
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check if storing data from TEE (external call)
                let has_tee_call = window.iter().any(|&b| matches!(b, 0xF1 | 0xFA));
                
                if has_tee_call {
                    // Check for monotonic counter/version validation
                    let has_version_check = window.windows(2).any(|w| {
                        w[0] == 0x54 && matches!(w[1], 0x10 | 0x11) // SLOAD + comparison (version check)
                    });
                    
                    // Check for block number anchoring
                    let has_block_anchor = window.iter().any(|&b| b == 0x43); // NUMBER
                    
                    if !has_version_check && !has_block_anchor {
                        vulns.push(TeeVulnerability {
                            pc,
                            vulnerability_type: "RollbackAttackVulnerability".to_string(),
                            description: format!(
                                "TEE state update at PC {} without rollback protection. \
                                Missing defenses: monotonic counter validation, version number enforcement, \
                                blockchain height anchoring. Attacker with TEE access can: rollback TEE state \
                                to previous version, replay old TEE outputs, violate state monotonicity guarantees. \
                                Critical for preventing TEE reset attacks and ensuring forward progress. \
                                Should enforce strictly increasing counters or block height validation.",
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
}
