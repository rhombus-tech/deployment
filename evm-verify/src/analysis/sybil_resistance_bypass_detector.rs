use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SybilVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct SybilResistanceBypassDetector {
    bytecode: Vec<u8>,
}

impl SybilResistanceBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SybilVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_address_only_verification());
        vulnerabilities.extend(self.detect_missing_uniqueness_proof());
        vulnerabilities.extend(self.detect_weak_identity_binding());

        vulnerabilities
    }

    fn detect_address_only_verification(&self) -> Vec<SybilVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // SSTORE registering identity
            if opcode == 0x55 {
                let start = if pc > 80 { pc - 80 } else { 0 };
                
                // Check if only uses CALLER (simple address)
                let has_caller = self.bytecode[start..pc].iter().any(|&b| b == 0x33);
                
                // Check for additional verification (ecrecover, proofs)
                let has_signature = self.bytecode[start..pc].windows(2).any(|w| w[0] == 0x60 && w[1] == 0x01); // ecrecover
                let has_proof_check = self.bytecode[start..pc].iter().any(|&b| b == 0x20); // KECCAK256
                
                if has_caller && !has_signature && !has_proof_check {
                    vulns.push(SybilVulnerability {
                        pc,
                        vulnerability_type: "AddressOnlyIdentity".to_string(),
                        description: format!(
                            "Identity registration at PC {} uses address alone. Trivial Sybil attack: \
                            attacker creates unlimited addresses for multiple identities. Each address = new identity. \
                            Bypasses: (1) Voting limits, (2) Airdrops, (3) Reputation systems. Require proof of \
                            unique personhood (WorldID, BrightID, or stake requirement).",
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

    fn detect_missing_uniqueness_proof(&self) -> Vec<SybilVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // SSTORE identity storage
            if opcode == 0x55 {
                let start = if pc > 100 { pc - 100 } else { 0 };
                
                // Check for ZK proof verification (bn256Pairing)
                let has_pairing = self.bytecode[start..pc].windows(2).any(|w| w[0] == 0x60 && w[1] == 0x08);
                
                // Check for biometric/credential verification
                let has_verification = self.bytecode[start..pc].iter().filter(|&&b| b == 0xF1 || b == 0xFA).count();
                
                // Check for economic stake (value transfer)
                let has_stake = self.bytecode[start..pc].iter().any(|&b| b == 0x34); // CALLVALUE
                
                if !has_pairing && has_verification < 2 && !has_stake {
                    vulns.push(SybilVulnerability {
                        pc,
                        vulnerability_type: "MissingUniquenessProof".to_string(),
                        description: format!(
                            "Identity system at PC {} lacks uniqueness verification. No proof user is unique human. \
                            Sybil attack vectors: (1) Bot farms create thousands of identities, (2) Vote manipulation, \
                            (3) Airdrop farming. Solutions: (1) ZK proof of personhood (WorldID), (2) Social graph analysis, \
                            (3) Economic stake requirement.",
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

    fn detect_weak_identity_binding(&self) -> Vec<SybilVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // SSTORE identity mapping
            if opcode == 0x55 {
                let start = if pc > 60 { pc - 60 } else { 0 };
                
                // Check if identity can be changed/transferred
                let has_update_logic = self.bytecode[start..pc].iter().filter(|&&b| b == 0x54).count() >= 1;
                
                // Check for immutability enforcement (no update after first set)
                let has_initialization_check = self.bytecode[start..pc].iter().any(|&b| b == 0x15); // ISZERO
                
                if has_update_logic && !has_initialization_check {
                    vulns.push(SybilVulnerability {
                        pc,
                        vulnerability_type: "WeakIdentityBinding".to_string(),
                        description: format!(
                            "Identity at PC {} appears mutable. Identity transfer enables: (1) Selling verified identities, \
                            (2) Reputation washing, (3) Sybil multiplication. Once identity verified, should be permanently \
                            bound to address. Add: require(!identitySet[addr]).",
                            pc
                        ),
                        confidence: 0.70,
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
