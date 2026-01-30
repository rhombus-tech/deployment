use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffChainSignatureVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct OffChainSignatureTimestampManipulationDetector {
    bytecode: Vec<u8>,
}

impl OffChainSignatureTimestampManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<OffChainSignatureVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_missing_timestamp_validation());
        vulnerabilities.extend(self.detect_timestamp_replay_window());
        vulnerabilities.extend(self.detect_server_time_dependency());

        vulnerabilities
    }

    fn detect_missing_timestamp_validation(&self) -> Vec<OffChainSignatureVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // ECRECOVER signature verification
            if opcode == 0x60 && pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x01 {
                // Check for ECRECOVER precompile call
                let window_end = (pc + 50).min(self.bytecode.len());
                let has_staticcall = self.bytecode[pc..window_end].iter().any(|&b| b == 0xFA);
                
                if has_staticcall {
                    // Look for timestamp comparison after signature verification
                    let mut check_pc = pc + 50;
                    let mut has_timestamp = false;
                    let mut has_comparison = false;
                    let mut instructions = 0;

                    while check_pc < self.bytecode.len() && instructions < 80 {
                        let check_op = self.bytecode[check_pc];
                        
                        if check_op == 0x42 { // TIMESTAMP
                            has_timestamp = true;
                        }
                        
                        if matches!(check_op, 0x10 | 0x11 | 0x12 | 0x13) { // LT, GT, SLT, SGT
                            has_comparison = true;
                        }
                        
                        check_pc += 1;
                        instructions += 1;
                        
                        if check_op >= 0x60 && check_op <= 0x7F {
                            check_pc += (check_op - 0x5F) as usize;
                        }
                    }

                    if !has_timestamp || !has_comparison {
                        vulns.push(OffChainSignatureVulnerability {
                            pc,
                            vulnerability_type: "MissingTimestampValidation".to_string(),
                            description: format!(
                                "Off-chain signature verification at PC {} without timestamp validation. \
                                Missing checks for: signature creation time, expiration window, and staleness. \
                                Attacker can replay old signatures indefinitely, use pre-signed messages after \
                                context changes, or frontrun with expired signatures.",
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

    fn detect_timestamp_replay_window(&self) -> Vec<OffChainSignatureVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // TIMESTAMP opcode followed by arithmetic
            if opcode == 0x42 {
                let mut check_pc = pc + 1;
                let mut has_large_window = false;
                let mut has_no_upper_bound = true;
                let mut instructions = 0;

                while check_pc < self.bytecode.len() && instructions < 30 {
                    let check_op = self.bytecode[check_pc];
                    
                    // Check for large time constants (> 1 day = 86400 seconds)
                    if check_op == 0x61 && check_pc + 2 < self.bytecode.len() {
                        let value = u16::from_be_bytes([
                            self.bytecode[check_pc + 1],
                            self.bytecode[check_pc + 2],
                        ]);
                        if value > 337 { // 86400 / 256 = ~337 (rough check for large values)
                            has_large_window = true;
                        }
                    }
                    
                    // Check for upper bound comparison (future timestamp check)
                    if matches!(check_op, 0x10 | 0x11) { // LT, GT
                        has_no_upper_bound = false;
                    }
                    
                    check_pc += 1;
                    instructions += 1;
                    
                    if check_op >= 0x60 && check_op <= 0x7F {
                        check_pc += (check_op - 0x5F) as usize;
                    }
                }

                if has_large_window || has_no_upper_bound {
                    vulns.push(OffChainSignatureVulnerability {
                        pc,
                        vulnerability_type: "TimestampReplayWindow".to_string(),
                        description: format!(
                            "Timestamp validation at PC {} with excessive replay window or no upper bound. \
                            Vulnerable to: extended signature validity periods (> 1 day), future-dated signatures, \
                            and clock skew attacks. Attacker can generate signatures with manipulated timestamps \
                            or exploit delayed execution windows.",
                            pc
                        ),
                        confidence: 0.82,
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

    fn detect_server_time_dependency(&self) -> Vec<OffChainSignatureVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut timestamp_uses = 0;
        let mut nonce_uses = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP
                timestamp_uses += 1;
            }
            
            // Look for nonce-based replay protection (SLOAD followed by incrementation)
            if opcode == 0x54 { // SLOAD
                let window_end = (pc + 10).min(self.bytecode.len());
                if self.bytecode[pc..window_end].iter().any(|&b| b == 0x01) { // ADD (nonce++)
                    nonce_uses += 1;
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        // If using timestamps but no nonce-based replay protection
        if timestamp_uses > 0 && nonce_uses == 0 {
            vulns.push(OffChainSignatureVulnerability {
                pc: 0,
                vulnerability_type: "ServerTimeDependency".to_string(),
                description: format!(
                    "Contract relies on server-provided timestamps ({} uses) without nonce-based replay protection. \
                    Vulnerable to: timestamp manipulation by off-chain servers, clock synchronization attacks, \
                    and timezone exploitation. Missing chain-based nonce or sequential ordering enforcement. \
                    Attacker controlling signature server can manipulate validity windows.",
                    timestamp_uses
                ),
                confidence: 0.79,
            });
        }

        vulns
    }
}
