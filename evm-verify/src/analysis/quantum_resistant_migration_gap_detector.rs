use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationGapVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct QuantumResistantMigrationGapDetector {
    bytecode: Vec<u8>,
}

impl QuantumResistantMigrationGapDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<MigrationGapVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if contract uses crypto precompiles but lacks upgradability
        if self.uses_crypto_precompiles() && !self.has_upgrade_mechanism() {
            vulnerabilities.push(MigrationGapVulnerability {
                pc: 0,
                vulnerability_type: "NoUpgradePath".to_string(),
                description: "Contract uses cryptographic precompiles without upgrade mechanism. \
                    Cannot migrate to post-quantum algorithms when needed. Consider using proxy pattern (DELEGATECALL).".to_string(),
                confidence: 0.90,
            });
        }

        // Check for immutable crypto parameters in storage
        vulnerabilities.extend(self.detect_immutable_crypto_storage());

        vulnerabilities
    }

    fn uses_crypto_precompiles(&self) -> bool {
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Check for PUSH followed by precompile addresses
            if opcode == 0x60 && pc + 1 < self.bytecode.len() {
                let addr = self.bytecode[pc + 1];
                // Precompiles 0x01 (ecrecover), 0x05 (modexp), 0x06-0x09 (bn256/bls12)
                if addr == 0x01 || addr == 0x05 || (0x06..=0x09).contains(&addr) {
                    return true;
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }
        false
    }

    fn has_upgrade_mechanism(&self) -> bool {
        // Check for DELEGATECALL (proxy pattern)
        let has_delegatecall = self.bytecode.iter().any(|&b| b == 0xF4);
        
        // Check for EIP-1967 storage slot (implementation address)
        let has_proxy_slot = self.bytecode.windows(4).any(|w| {
            w == [0x36, 0x08, 0x94, 0xa1] // EIP-1967 implementation slot prefix
        });
        
        has_delegatecall || has_proxy_slot
    }

    fn detect_immutable_crypto_storage(&self) -> Vec<MigrationGapVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        
        // Look for SSTORE operations that might store crypto config
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            if opcode == 0x55 { // SSTORE
                // Check if this storage write is in constructor (between CODECOPY and first JUMPDEST)
                let is_constructor = pc < 200; // Heuristic: first 200 bytes usually constructor
                
                if is_constructor {
                    // Storage writes in constructor are often immutable configs
                    vulns.push(MigrationGapVulnerability {
                        pc,
                        vulnerability_type: "ImmutableCryptoConfig".to_string(),
                        description: format!(
                            "Storage write at PC {} in constructor suggests immutable cryptographic configuration. \
                            If this stores algorithm selectors or crypto parameters, migration to post-quantum \
                            algorithms will be impossible.",
                            pc
                        ),
                        confidence: 0.65,
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
