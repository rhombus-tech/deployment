use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcParameterVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct EllipticCurveParameterInjectionDetector {
    bytecode: Vec<u8>,
}

impl EllipticCurveParameterInjectionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<EcParameterVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unvalidated_ec_ops());
        vulnerabilities.extend(self.detect_calldataload_to_ecmul());
        vulnerabilities.extend(self.detect_ecrecover_without_validation());

        vulnerabilities
    }

    fn detect_unvalidated_ec_ops(&self) -> Vec<EcParameterVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Check for bn256Add (0x06) or bn256Mul (0x07) precompiles
            if opcode == 0x60 && pc + 1 < self.bytecode.len() {
                let addr = self.bytecode[pc + 1];
                if addr == 0x06 || addr == 0x07 {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let mut has_call = false;
                    let mut has_validation = false;
                    
                    for check_pc in (pc + 2)..window_end {
                        if self.bytecode[check_pc] == 0xFA || self.bytecode[check_pc] == 0xF1 {
                            has_call = true;
                        }
                        // Check for modulo or range validation before call
                        if self.bytecode[check_pc] == 0x06 || self.bytecode[check_pc] == 0x09 {
                            has_validation = true;
                        }
                    }
                    
                    if has_call && !has_validation {
                        vulns.push(EcParameterVulnerability {
                            pc,
                            vulnerability_type: "UnvalidatedEcOperation".to_string(),
                            description: format!(
                                "EC precompile call at PC {} without point validation. Invalid curve attacks: \
                                attacker provides point not on curve, causing incorrect crypto results. \
                                Validate: (1) Point on curve: y² = x³ + ax + b, (2) Point in correct subgroup, \
                                (3) Coordinates within field prime.",
                                pc
                            ),
                            confidence: 0.75,
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

    fn detect_calldataload_to_ecmul(&self) -> Vec<EcParameterVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // CALLDATALOAD getting user input
            if opcode == 0x35 {
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[(pc + 1)..window_end];
                
                // Check if loaded data used with EC precompiles
                let has_ec_precompile = window.windows(2).any(|w| {
                    w[0] == 0x60 && (w[1] == 0x06 || w[1] == 0x07 || w[1] == 0x08)
                });
                
                // Check for validation (MOD operation on loaded data)
                let has_mod = window.iter().any(|&b| b == 0x06);
                
                if has_ec_precompile && !has_mod {
                    vulns.push(EcParameterVulnerability {
                        pc,
                        vulnerability_type: "CalldataToEcPrecompile".to_string(),
                        description: format!(
                            "User input at PC {} flows to EC precompile without validation. Attacker controls \
                            curve points. Can provide: (1) Invalid points for wrong results, (2) Points with \
                            small order for key recovery, (3) Points on twist curve. Validate all user-supplied \
                            EC parameters before cryptographic operations.",
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

    fn detect_ecrecover_without_validation(&self) -> Vec<EcParameterVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // ecrecover precompile (0x01)
            if opcode == 0x60 && pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x01 {
                let window_end = (pc + 70).min(self.bytecode.len());
                let mut has_staticcall = false;
                let mut has_zero_check = false;
                
                for check_pc in (pc + 2)..window_end {
                    if self.bytecode[check_pc] == 0xFA {
                        has_staticcall = true;
                        
                        // Check if result validated (ISZERO check for failure)
                        let result_window_end = (check_pc + 20).min(self.bytecode.len());
                        has_zero_check = self.bytecode[(check_pc + 1)..result_window_end]
                            .iter().any(|&b| b == 0x15); // ISZERO
                        break;
                    }
                }
                
                if has_staticcall && !has_zero_check {
                    vulns.push(EcParameterVulnerability {
                        pc,
                        vulnerability_type: "EcrecoverWithoutValidation".to_string(),
                        description: format!(
                            "ecrecover at PC {} without checking for address(0) return. Invalid signatures \
                            return 0x0, which may pass authorization if not checked. Also vulnerable to \
                            signature malleability (s value manipulation). Check: (1) result != 0, \
                            (2) s in lower half of curve order.",
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
