use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct QuantumVulnerableSignatureSchemeDetector {
    bytecode: Vec<u8>,
}

impl QuantumVulnerableSignatureSchemeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<QuantumVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Scan for ECRECOVER precompile calls (address 0x01)
        vulnerabilities.extend(self.detect_ecrecover_usage());
        
        // Scan for modexp precompile (RSA operations at 0x05)
        vulnerabilities.extend(self.detect_rsa_usage());
        
        // Check for hardcoded signature verification without upgradability
        if self.lacks_crypto_upgradability() {
            vulnerabilities.push(QuantumVulnerability {
                pc: 0,
                vulnerability_type: "NoQuantumMigrationPath".to_string(),
                description: "Contract uses cryptographic operations without upgrade mechanism for post-quantum transition".to_string(),
                confidence: 0.75,
            });
        }

        vulnerabilities
    }

    fn detect_ecrecover_usage(&self) -> Vec<QuantumVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for PUSH1 0x01 (ecrecover precompile address)
            if opcode == 0x60 && pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x01 {
                // Check if followed by STATICCALL or CALL within next 20 bytes
                let window_end = (pc + 30).min(self.bytecode.len());
                for check_pc in (pc + 2)..window_end {
                    if self.bytecode[check_pc] == 0xFA || self.bytecode[check_pc] == 0xF1 {
                        vulns.push(QuantumVulnerability {
                            pc,
                            vulnerability_type: "ECDSAUsage".to_string(),
                            description: format!(
                                "ECDSA signature verification via ecrecover at PC {}. Vulnerable to Shor's quantum algorithm. \
                                ECDSA relies on elliptic curve discrete logarithm which quantum computers can break.",
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

    fn detect_rsa_usage(&self) -> Vec<QuantumVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for PUSH1 0x05 (modexp precompile for RSA)
            if opcode == 0x60 && pc + 1 < self.bytecode.len() && self.bytecode[pc + 1] == 0x05 {
                let window_end = (pc + 30).min(self.bytecode.len());
                for check_pc in (pc + 2)..window_end {
                    if self.bytecode[check_pc] == 0xFA || self.bytecode[check_pc] == 0xF1 {
                        vulns.push(QuantumVulnerability {
                            pc,
                            vulnerability_type: "RSAUsage".to_string(),
                            description: format!(
                                "RSA-based cryptography via modexp precompile at PC {}. Vulnerable to Shor's algorithm. \
                                RSA factorization problem is efficiently solvable by quantum computers.",
                                pc
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

    fn lacks_crypto_upgradability(&self) -> bool {
        // Check for DELEGATECALL (0xF4) which suggests upgradability
        let has_delegatecall = self.bytecode.iter().any(|&b| b == 0xF4);
        
        // Check for storage writes that might indicate upgrade mechanism
        let has_upgrade_pattern = self.has_implementation_slot_pattern();
        
        // If contract uses crypto but has no upgrade mechanism, it's vulnerable
        let uses_crypto = self.bytecode.iter().any(|&b| b == 0x01) || // ecrecover address
                         self.bytecode.iter().any(|&b| b == 0x05);   // modexp address
        
        uses_crypto && !has_delegatecall && !has_upgrade_pattern
    }
    
    fn has_implementation_slot_pattern(&self) -> bool {
        // Look for EIP-1967 implementation slot pattern
        // 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
        let eip1967_bytes = [0x36, 0x08, 0x94, 0xa1];
        self.bytecode.windows(4).any(|w| w == eip1967_bytes)
    }
}
