use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalleabilityVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct SignatureMalleabilityAdvancedDetector {
    bytecode: Vec<u8>,
}

impl SignatureMalleabilityAdvancedDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<MalleabilityVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_ecrecover_without_s_check());
        vulnerabilities.extend(self.detect_signature_used_as_key());
        vulnerabilities.extend(self.detect_v_value_validation());

        vulnerabilities
    }

    fn detect_ecrecover_without_s_check(&self) -> Vec<MalleabilityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            if opcode == 0x60 && pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x01 {
                let window_end = (pc + 100).min(self.bytecode.len());
                let mut has_ecrecover = false;
                let mut has_s_validation = false;
                
                for check_pc in (pc + 2)..window_end {
                    if self.bytecode[check_pc] == 0xFA {
                        has_ecrecover = true;
                        
                        // Check for s value validation before ecrecover
                        // Pattern: load s, compare with half curve order
                        let sig_start = if check_pc > 80 { check_pc - 80 } else { 0 };
                        let sig_window = &self.bytecode[sig_start..check_pc];
                        
                        // Look for GT comparison (s > N/2 check)
                        let has_comparison = sig_window.iter().any(|&b| b == 0x11 || b == 0x10);
                        // Look for large constant (curve order N/2)
                        let has_large_constant = sig_window.windows(2).any(|w| w[0] >= 0x61 && w[0] <= 0x7F);
                        
                        has_s_validation = has_comparison && has_large_constant;
                        break;
                    }
                }
                
                if has_ecrecover && !has_s_validation {
                    vulns.push(MalleabilityVulnerability {
                        pc,
                        vulnerability_type: "MalleableSignature".to_string(),
                        description: format!(
                            "ecrecover at PC {} without s-value validation. Signature malleability: for signature \
                            (r, s, v), attacker can create valid signature (r, -s mod n, v') with different hash. \
                            This allows: (1) Signature replay with different transaction ID, (2) Double-spending if \
                            signature used as unique identifier. Validate: require(uint256(s) <= 0x7FFFFFFFFFFFFFFF...).",
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

    fn detect_signature_used_as_key(&self) -> Vec<MalleabilityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for KECCAK256 followed by SSTORE (using signature hash as storage key)
            if opcode == 0x20 {
                let window_end = (pc + 40).min(self.bytecode.len());
                let mut has_sstore = false;
                let mut preceded_by_calldataload = false;
                
                // Check if KECCAK256 is hashing calldata (signature)
                let start = if pc > 30 { pc - 30 } else { 0 };
                preceded_by_calldataload = self.bytecode[start..pc].iter().any(|&b| b == 0x35);
                
                // Check if hash result used in SSTORE
                for check_pc in (pc + 1)..window_end {
                    if self.bytecode[check_pc] == 0x55 {
                        has_sstore = true;
                        break;
                    }
                }
                
                if preceded_by_calldataload && has_sstore {
                    vulns.push(MalleabilityVulnerability {
                        pc,
                        vulnerability_type: "SignatureAsStorageKey".to_string(),
                        description: format!(
                            "Signature hash at PC {} used as storage key. Due to malleability, same logical \
                            signature has two valid forms with different hashes. Attacker can: (1) Submit both \
                            forms to create duplicate state entries, (2) Bypass replay protection keyed by \
                            signature hash. Use recovered address + nonce as key instead.",
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

    fn detect_v_value_validation(&self) -> Vec<MalleabilityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            if opcode == 0x60 && pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x01 {
                let window_end = (pc + 80).min(self.bytecode.len());
                let mut has_ecrecover = false;
                let mut has_v_validation = false;
                
                for check_pc in (pc + 2)..window_end {
                    if self.bytecode[check_pc] == 0xFA {
                        has_ecrecover = true;
                        
                        // Check for v value validation (v == 27 || v == 28)
                        let v_start = if check_pc > 60 { check_pc - 60 } else { 0 };
                        let v_window = &self.bytecode[v_start..check_pc];
                        
                        // Look for comparison with 27 or 28
                        let has_27_or_28 = v_window.windows(2).any(|w| {
                            w[0] == 0x60 && (w[1] == 27 || w[1] == 28)
                        });
                        let has_eq = v_window.iter().any(|&b| b == 0x14);
                        
                        has_v_validation = has_27_or_28 && has_eq;
                        break;
                    }
                }
                
                if has_ecrecover && !has_v_validation {
                    vulns.push(MalleabilityVulnerability {
                        pc,
                        vulnerability_type: "InvalidVValue".to_string(),
                        description: format!(
                            "ecrecover at PC {} without v-value validation. V must be 27 or 28 (or 0/1 with EIP-155). \
                            Invalid v values can: (1) Cause ecrecover to return wrong address, (2) Enable signature \
                            malleability exploits, (3) Break assumptions about signature uniqueness. \
                            Validate: require(v == 27 || v == 28).",
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
}
