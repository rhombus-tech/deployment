use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VrfVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct VrfOutputManipulationDetector {
    bytecode: Vec<u8>,
}

impl VrfOutputManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<VrfVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect KECCAK256 followed by MOD (modulo bias in randomness)
        vulnerabilities.extend(self.detect_modulo_bias());
        
        // Detect multiple KECCAK256 calls in loop (retrying randomness)
        vulnerabilities.extend(self.detect_randomness_grinding());
        
        // Detect randomness usage without external verification
        vulnerabilities.extend(self.detect_unverified_randomness());

        vulnerabilities
    }

    fn detect_modulo_bias(&self) -> Vec<VrfVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for KECCAK256 followed by MOD operation
            if opcode == 0x20 { // KECCAK256
                let window_end = (pc + 15).min(self.bytecode.len());
                for check_pc in (pc + 1)..window_end {
                    if self.bytecode[check_pc] == 0x06 { // MOD
                        vulns.push(VrfVulnerability {
                            pc,
                            vulnerability_type: "VRFModuloBias".to_string(),
                            description: format!(
                                "KECCAK256 at PC {} followed by MOD at PC {}. Modulo operation on hash output \
                                creates bias in randomness distribution. For range [0, N), values < (2^256 mod N) \
                                appear more frequently. This allows attackers to predict/bias VRF outputs. \
                                Use rejection sampling or cryptographically-secure range reduction instead.",
                                pc, check_pc
                            ),
                            confidence: 0.90,
                        });
                        break;
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

    fn detect_randomness_grinding(&self) -> Vec<VrfVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut keccak_count = 0;
        let mut last_keccak_pc = 0;
        let mut in_loop = false;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Detect loop pattern (backward JUMPI)
            if opcode == 0x57 { // JUMPI
                // Check if this could be a loop (jumping backwards)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let has_jumpdest_before = self.bytecode[start..pc].iter().any(|&b| b == 0x5B);
                in_loop = has_jumpdest_before;
            }
            
            if opcode == 0x20 { // KECCAK256
                if in_loop {
                    if last_keccak_pc > 0 && pc - last_keccak_pc < 50 {
                        keccak_count += 1;
                        if keccak_count >= 2 {
                            vulns.push(VrfVulnerability {
                                pc: last_keccak_pc,
                                vulnerability_type: "RandomnessGrinding".to_string(),
                                description: format!(
                                    "Multiple KECCAK256 operations in loop starting at PC {}. Pattern suggests \
                                    randomness grinding attack where attacker repeatedly generates randomness \
                                    until favorable outcome. In VRF context, this allows selective disclosure \
                                    of outputs, defeating unpredictability guarantees. Implement commit-reveal \
                                    with penalties for non-reveal.",
                                    last_keccak_pc
                                ),
                                confidence: 0.85,
                            });
                            keccak_count = 0;
                        }
                    } else {
                        keccak_count = 1;
                    }
                    last_keccak_pc = pc;
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_unverified_randomness(&self) -> Vec<VrfVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut has_keccak = false;
        let mut has_verification = false;

        // Scan for KECCAK256 usage (randomness generation)
        while pc < self.bytecode.len() {
            if self.bytecode[pc] == 0x20 {
                has_keccak = true;
                break;
            }
            pc += 1;
        }

        if !has_keccak {
            return vulns;
        }

        // Scan for verification patterns (ecrecover for VRF proof verification)
        pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Check for ecrecover precompile (0x01) or modexp (0x05) for VRF verification
            if opcode == 0x60 && pc + 1 < self.bytecode.len() {
                let addr = self.bytecode[pc + 1];
                if addr == 0x01 || addr == 0x05 { // ecrecover or modexp
                    has_verification = true;
                    break;
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        if has_keccak && !has_verification {
            vulns.push(VrfVulnerability {
                pc: 0,
                vulnerability_type: "UnverifiedRandomness".to_string(),
                description: "Contract generates randomness via KECCAK256 without cryptographic verification. \
                    True VRF requires proof that randomness was correctly generated and cannot be biased. \
                    Without verification (ecrecover/modexp for proof checking), operator can manipulate \
                    randomness by selective revelation. Implement proper VRF with cryptographic proofs \
                    (e.g., Chainlink VRF, RANDAO with verification).".to_string(),
                confidence: 0.75,
            });
        }

        vulns
    }
}
