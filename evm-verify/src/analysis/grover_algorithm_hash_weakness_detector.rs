use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroverVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct GroverAlgorithmHashWeaknessDetector {
    bytecode: Vec<u8>,
}

impl GroverAlgorithmHashWeaknessDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<GroverVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect SHA256 precompile usage (256-bit = 128-bit quantum security)
        vulnerabilities.extend(self.detect_sha256_usage());
        
        // Detect KECCAK256 usage (256-bit = 128-bit quantum security)
        vulnerabilities.extend(self.detect_keccak256_usage());
        
        // Detect RIPEMD160 usage (160-bit = 80-bit quantum security - broken!)
        vulnerabilities.extend(self.detect_ripemd160_usage());

        vulnerabilities
    }

    fn detect_sha256_usage(&self) -> Vec<GroverVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // SHA256 precompile is at address 0x02
            if opcode == 0x60 && pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x02 {
                let window_end = (pc + 30).min(self.bytecode.len());
                for check_pc in (pc + 2)..window_end {
                    if self.bytecode[check_pc] == 0xFA || self.bytecode[check_pc] == 0xF1 {
                        vulns.push(GroverVulnerability {
                            pc,
                            vulnerability_type: "SHA256GroverWeakness".to_string(),
                            description: format!(
                                "SHA-256 hash at PC {}. Grover's algorithm reduces 256-bit security to 128-bit. \
                                For collision resistance, this drops to 85-bit quantum security. \
                                Consider using SHA-512 or SHA3-512 for 256-bit post-quantum security.",
                                pc
                            ),
                            confidence: 0.95,
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

    fn detect_keccak256_usage(&self) -> Vec<GroverVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // KECCAK256 (SHA3) opcode is 0x20
            if opcode == 0x20 {
                vulns.push(GroverVulnerability {
                    pc,
                    vulnerability_type: "KECCAK256GroverWeakness".to_string(),
                    description: format!(
                        "KECCAK-256 at PC {}. Grover's algorithm provides quadratic speedup for preimage search. \
                        256-bit output provides only 128-bit quantum security. For long-term security against \
                        quantum computers, consider application-level use of SHA3-512 or other 512-bit hashes.",
                        pc
                    ),
                    confidence: 0.85,
                });
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }
        vulns
    }

    fn detect_ripemd160_usage(&self) -> Vec<GroverVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // RIPEMD-160 precompile at address 0x03
            if opcode == 0x60 && pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x03 {
                let window_end = (pc + 30).min(self.bytecode.len());
                for check_pc in (pc + 2)..window_end {
                    if self.bytecode[check_pc] == 0xFA || self.bytecode[check_pc] == 0xF1 {
                        vulns.push(GroverVulnerability {
                            pc,
                            vulnerability_type: "RIPEMD160Critical".to_string(),
                            description: format!(
                                "RIPEMD-160 at PC {} - CRITICAL! 160-bit hash provides only 80-bit quantum security \
                                with Grover's algorithm. This is BROKEN against quantum computers. \
                                Immediately migrate to SHA3-256 (128-bit quantum) or SHA3-512 (256-bit quantum).",
                                pc
                            ),
                            confidence: 1.0,
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
}
