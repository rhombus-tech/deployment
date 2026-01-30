use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarvestLaterVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct HarvestNowDecryptLaterRiskDetector {
    bytecode: Vec<u8>,
}

impl HarvestNowDecryptLaterRiskDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<HarvestLaterVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect SSTORE operations that might store encrypted data
        vulnerabilities.extend(self.detect_encrypted_storage_writes());
        
        // Check for symmetric encryption (AES precompile doesn't exist, so look for custom impl)
        vulnerabilities.extend(self.detect_symmetric_crypto_usage());
        
        // Check if data is stored long-term without key rotation
        if self.stores_data_without_rotation() {
            vulnerabilities.push(HarvestLaterVulnerability {
                pc: 0,
                vulnerability_type: "NoKeyRotation".to_string(),
                description: "Contract stores encrypted data without key rotation mechanism. \
                    Adversaries can harvest encrypted data now and decrypt with quantum computers later.".to_string(),
                confidence: 0.70,
            });
        }

        vulnerabilities
    }

    fn detect_encrypted_storage_writes(&self) -> Vec<HarvestLaterVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for SSTORE (0x55) preceded by XOR operations (potential encryption)
            if opcode == 0x55 {
                // Check preceding 50 bytes for XOR (0x18) which suggests encryption
                let start = if pc > 50 { pc - 50 } else { 0 };
                let has_xor = self.bytecode[start..pc].iter().any(|&b| b == 0x18);
                
                // Check for SHA3/KECCAK256 (0x20) suggesting key derivation
                let has_hash = self.bytecode[start..pc].iter().any(|&b| b == 0x20);
                
                if has_xor && has_hash {
                    vulns.push(HarvestLaterVulnerability {
                        pc,
                        vulnerability_type: "EncryptedStorageWrite".to_string(),
                        description: format!(
                            "Encrypted data written to storage at PC {}. XOR and hashing patterns suggest encryption. \
                            If using classical encryption (AES, ChaCha20), this is vulnerable to quantum attacks. \
                            Adversaries can copy blockchain state now and decrypt later with quantum computers.",
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

    fn detect_symmetric_crypto_usage(&self) -> Vec<HarvestLaterVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut xor_count = 0;
        let mut shift_count = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            match opcode {
                0x18 => xor_count += 1,  // XOR
                0x1B | 0x1C => shift_count += 1,  // SHL, SHR (used in block ciphers)
                _ => {}
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        // Heavy XOR and shift usage suggests custom symmetric encryption
        if xor_count > 20 && shift_count > 10 {
            vulns.push(HarvestLaterVulnerability {
                pc: 0,
                vulnerability_type: "CustomSymmetricCrypto".to_string(),
                description: format!(
                    "Custom symmetric encryption implementation detected ({} XOR ops, {} shift ops). \
                    Symmetric encryption (AES-256, ChaCha20) provides ~128-bit quantum security vs 256-bit classical. \
                    Grover's algorithm reduces effective key size by half. Data encrypted today can be harvested \
                    and decrypted with future quantum computers.",
                    xor_count, shift_count
                ),
                confidence: 0.75,
            });
        }

        vulns
    }

    fn stores_data_without_rotation(&self) -> bool {
        // Check if contract has SSTORE but no time-based rotation logic
        let has_storage_writes = self.bytecode.iter().any(|&b| b == 0x55);
        
        // Look for TIMESTAMP (0x42) or NUMBER (0x43) used with storage
        let has_time_logic = self.bytecode.windows(20).any(|window| {
            window.iter().any(|&b| b == 0x42 || b == 0x43) && 
            window.iter().any(|&b| b == 0x55)
        });
        
        // If storing data but no time-based logic, likely no rotation
        has_storage_writes && !has_time_logic
    }
}
