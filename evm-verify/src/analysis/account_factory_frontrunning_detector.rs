use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountFactoryVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct AccountFactoryFrontrunningDetector {
    bytecode: Vec<u8>,
}

impl AccountFactoryFrontrunningDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<AccountFactoryVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_predictable_account_address());
        vulnerabilities.extend(self.detect_initialization_frontrunning());
        vulnerabilities.extend(self.detect_create2_salt_manipulation());

        vulnerabilities
    }

    fn detect_predictable_account_address(&self) -> Vec<AccountFactoryVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // CREATE2 opcode for deterministic deployment
            if opcode == 0xF5 {
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check salt derivation
                let has_caller_salt = window.iter().any(|&b| b == 0x33); // CALLER
                let has_hash_salt = window.iter().any(|&b| b == 0x20); // KECCAK256
                
                // Check for nonce or timestamp in salt
                let has_nonce = window.iter().any(|&b| b == 0x54); // SLOAD (nonce)
                let has_timestamp = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                
                if !has_caller_salt && !has_hash_salt && !has_nonce && !has_timestamp {
                    vulns.push(AccountFactoryVulnerability {
                        pc,
                        vulnerability_type: "PredictableAccountAddress".to_string(),
                        description: format!(
                            "ERC-4337 account factory CREATE2 at PC {} uses predictable salt. \
                            Attack: frontrunner predicts future account address, deposits malicious contract \
                            or ETH at that address first, griefing legitimate deployment. Missing entropy sources: \
                            user-specific data, factory nonce, block timestamp. Enables: address squatting, \
                            griefing attacks preventing account creation, malicious contract deployment at predicted address.",
                            pc
                        ),
                        confidence: 0.89,
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

    fn detect_initialization_frontrunning(&self) -> Vec<AccountFactoryVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // External call to initialize account (common pattern)
            if matches!(opcode, 0xF1 | 0xFA) {
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check if this is initialization call
                let has_calldata = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                // Look for account creation before this
                let has_create = window.iter().any(|&b| matches!(b, 0xF0 | 0xF5)); // CREATE, CREATE2
                
                if has_create && has_calldata {
                    // Check for initialization protection
                    let window_end = (pc + 50).min(self.bytecode.len());
                    let forward_window = &self.bytecode[pc..window_end];
                    
                    // Check for return value validation
                    let has_return_check = forward_window.iter().any(|&b| matches!(b, 0x15 | 0x16)); // ISZERO, NOT
                    let has_revert = forward_window.iter().any(|&b| b == 0xFD);
                    
                    // Check for initialization lock
                    let has_init_flag = window.windows(2).any(|w| w[0] == 0x54 && w[1] == 0x15); // SLOAD + ISZERO
                    
                    if !has_return_check && !has_revert && !has_init_flag {
                        vulns.push(AccountFactoryVulnerability {
                            pc,
                            vulnerability_type: "InitializationFrontrunning".to_string(),
                            description: format!(
                                "Account initialization call at PC {} vulnerable to frontrunning. \
                                Attack flow: (1) Factory creates account via CREATE2, (2) Frontrunner sees pending init tx, \
                                (3) Frontrunner calls initialize() first with malicious owner. Missing protections: \
                                initialization lock, atomic create+init, return value validation. Enables complete \
                                account takeover by frontrunning initialization transaction.",
                                pc
                            ),
                            confidence: 0.91,
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

    fn detect_create2_salt_manipulation(&self) -> Vec<AccountFactoryVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for salt computation before CREATE2
            if opcode == 0x20 { // KECCAK256 (salt derivation)
                let window_end = (pc + 60).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check if followed by CREATE2
                let has_create2 = window.iter().any(|&b| b == 0xF5);
                
                if has_create2 {
                    // Check salt input sources
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    // Check for user-controlled input
                    let has_calldata = pre_window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                    
                    // Check for validation of salt
                    let has_validation = pre_window.iter().any(|&b| matches!(b, 0x10 | 0x11 | 0x14)); // LT, GT, EQ
                    
                    // Check for collision prevention
                    let has_collision_check = window.windows(2).any(|w| {
                        w[0] == 0x3B && w[1] == 0x15 // EXTCODESIZE + ISZERO (checking if address empty)
                    });
                    
                    if has_calldata && !has_validation && !has_collision_check {
                        vulns.push(AccountFactoryVulnerability {
                            pc,
                            vulnerability_type: "Create2SaltManipulation".to_string(),
                            description: format!(
                                "CREATE2 salt derivation at PC {} accepts unvalidated user input. \
                                Manipulation risks: (1) User crafts salt to collide with existing account, \
                                (2) Salt chosen to create vulnerable address (many leading zeros for vanity), \
                                (3) Malicious salt causes deployment to fail, griefing user. Missing: salt validation, \
                                collision detection, address quality checks. Can lead to account deployment failures \
                                or security-reduced addresses.",
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
}
