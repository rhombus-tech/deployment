use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolanaAccountModelVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct SolanaSealevelAccountModelConfusionDetector {
    bytecode: Vec<u8>,
}

impl SolanaSealevelAccountModelConfusionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SolanaAccountModelVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_account_ownership_confusion());
        vulnerabilities.extend(self.detect_rent_exemption_bypass());
        vulnerabilities.extend(self.detect_program_derived_address_collision());

        vulnerabilities
    }

    fn detect_account_ownership_confusion(&self) -> Vec<SolanaAccountModelVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (account data modification)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_caller_check = window.iter().any(|&b| b == 0x33); // CALLER
                
                if has_caller_check {
                    let has_owner_validation = window.iter().filter(|&&b| b == 0x14).count() >= 2; // Multiple EQ checks
                    
                    if !has_owner_validation {
                        vulns.push(SolanaAccountModelVulnerability {
                            pc,
                            vulnerability_type: "AccountOwnershipConfusion".to_string(),
                            description: format!(
                                "Account modification at PC {} without owner verification. Solana account model: only \
                                owner program can modify account data. EVM storage model: any contract can write to any slot. \
                                Cross-chain bridge vulnerability: EVM contract modifies data it doesn't own on Solana side. \
                                Missing: explicit owner program check, program ID validation, cross-program invocation guard. \
                                Enables unauthorized account tampering when bridging to Solana.",
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

    fn detect_rent_exemption_bypass(&self) -> Vec<SolanaAccountModelVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF0 | 0xF5) { // CREATE, CREATE2 (account creation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_value = window.iter().any(|&b| b == 0x34); // CALLVALUE
                
                if has_value {
                    let has_minimum_balance = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_rent_calculation = window.iter().any(|&b| matches!(b, 0x02 | 0x04)); // MUL, DIV
                    
                    if !has_minimum_balance && !has_rent_calculation {
                        vulns.push(SolanaAccountModelVulnerability {
                            pc,
                            vulnerability_type: "RentExemptionBypass".to_string(),
                            description: format!(
                                "Account creation at PC {} without rent exemption enforcement. Solana requires accounts \
                                maintain minimum balance for rent exemption, or they're deleted. EVM has no rent concept. \
                                Bridge risk: creating accounts with insufficient balance on Solana causes automatic deletion, \
                                losing all data. Missing: rent exemption threshold calculation (2 years of rent), \
                                minimum balance enforcement, size-based rent formula. Enables account data loss.",
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

    fn detect_program_derived_address_collision(&self) -> Vec<SolanaAccountModelVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (address derivation)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_seed_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_seed_data {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_create = forward.iter().any(|&b| matches!(b, 0xF0 | 0xF5)); // CREATE, CREATE2
                    
                    if has_create {
                        let has_bump_seed = window.iter().any(|&b| b == 0x06); // MOD (bump seed derivation)
                        
                        if !has_bump_seed {
                            vulns.push(SolanaAccountModelVulnerability {
                                pc,
                                vulnerability_type: "ProgramDerivedAddressCollision".to_string(),
                                description: format!(
                                    "Address derivation at PC {} incompatible with Solana PDA (Program Derived Address). \
                                    Solana PDAs use ed25519 curve to find off-curve addresses with bump seeds ensuring no \
                                    private key exists. EVM CREATE2 uses keccak256 without curve check. Bridge vulnerability: \
                                    EVM-derived addresses may have private keys on Solana, allowing unauthorized access. \
                                    Missing: ed25519 curve validation, bump seed iteration, canonical PDA derivation. \
                                    Enables key-based attacks on supposedly keyless accounts.",
                                    pc
                                ),
                                confidence: 0.87,
                            });
                        }
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
