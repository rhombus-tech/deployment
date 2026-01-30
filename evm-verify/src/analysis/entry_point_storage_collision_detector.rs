use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPointVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct EntryPointStorageCollisionDetector {
    bytecode: Vec<u8>,
}

impl EntryPointStorageCollisionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<EntryPointVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_delegatecall_storage_overlap());
        vulnerabilities.extend(self.detect_unstructured_storage_collision());
        vulnerabilities.extend(self.detect_account_state_corruption());

        vulnerabilities
    }

    fn detect_delegatecall_storage_overlap(&self) -> Vec<EntryPointVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // DELEGATECALL to account implementation
            if opcode == 0xF4 {
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for storage slot calculation before DELEGATECALL
                let has_sload = window.iter().any(|&b| b == 0x54);
                let has_sstore = window.iter().any(|&b| b == 0x55);
                
                if has_sload || has_sstore {
                    // Check for EIP-1967 storage slot pattern (keccak256 - 1)
                    let has_keccak = window.iter().any(|&b| b == 0x20);
                    let has_sub = window.iter().any(|&b| b == 0x03); // SUB
                    
                    // Check for storage namespace isolation
                    let window_end = (pc + 50).min(self.bytecode.len());
                    let forward_window = &self.bytecode[pc..window_end];
                    let has_post_sstore = forward_window.iter().any(|&b| b == 0x55);
                    
                    if !has_keccak && !has_sub && has_post_sstore {
                        vulns.push(EntryPointVulnerability {
                            pc,
                            vulnerability_type: "DelegatecallStorageOverlap".to_string(),
                            description: format!(
                                "ERC-4337 EntryPoint DELEGATECALL at PC {} risks storage collision with account. \
                                Using sequential storage slots without namespace isolation. Vulnerability: account \
                                implementation writes to same slots as EntryPoint state (deposits, stakes, nonces), \
                                corrupting critical security variables. Missing: EIP-1967 slot derivation, storage \
                                gap protection, explicit namespace separation. Can lead to deposit theft or nonce bypass.",
                                pc
                            ),
                            confidence: 0.86,
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

    fn detect_unstructured_storage_collision(&self) -> Vec<EntryPointVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut storage_writes = Vec::new();

        // Collect all storage write locations
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE
                let start = if pc > 40 { pc - 40 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check if slot is computed (not hardcoded)
                let has_computation = window.iter().any(|&b| matches!(b, 0x01 | 0x02 | 0x20)); // ADD, MUL, KECCAK256
                
                storage_writes.push((pc, has_computation));
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        // Check if multiple storage writes without proper slot derivation
        let unstructured_writes = storage_writes.iter().filter(|(_, computed)| !computed).count();
        
        if unstructured_writes > 3 && storage_writes.len() > 5 {
            vulns.push(EntryPointVulnerability {
                pc: storage_writes[0].0,
                vulnerability_type: "UnstructuredStorageCollision".to_string(),
                description: format!(
                    "EntryPoint uses {} unstructured storage slots (of {} total) without collision-resistant derivation. \
                    Risk: account implementations using same slot numbers overwrite EntryPoint state. Critical variables \
                    at risk: user deposits mapping, stake balances, nonce tracking. Missing: keccak256-based slot derivation, \
                    storage layout documentation, slot reservation gaps. Accounts can accidentally or maliciously corrupt \
                    EntryPoint security state.",
                    unstructured_writes, storage_writes.len()
                ),
                confidence: 0.83,
            });
        }

        vulns
    }

    fn detect_account_state_corruption(&self) -> Vec<EntryPointVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for nonce management (critical for replay protection)
            if opcode == 0x54 { // SLOAD
                let window_end = (pc + 50).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check for nonce increment pattern
                let has_add = window.iter().any(|&b| b == 0x01); // ADD
                let has_sstore = window.iter().any(|&b| b == 0x55); // SSTORE
                
                if has_add && has_sstore {
                    // Check for nonce corruption protection
                    let start = if pc > 60 { pc - 60 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    // Check for mutex/reentrancy guard
                    let has_reentrancy_guard = pre_window.windows(2).any(|w| {
                        w[0] == 0x54 && w[1] == 0x15 // SLOAD + ISZERO (checking lock)
                    });
                    
                    // Check for atomic increment validation
                    let has_overflow_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if !has_reentrancy_guard && !has_overflow_check {
                        vulns.push(EntryPointVulnerability {
                            pc,
                            vulnerability_type: "AccountStateCorruption".to_string(),
                            description: format!(
                                "Nonce increment at PC {} vulnerable to state corruption via reentrancy. \
                                Missing protections: reentrancy lock during nonce update, atomic increment validation, \
                                overflow protection. Attack: reentrant call during UserOp execution corrupts nonce state, \
                                allowing replay attacks or nonce skipping. Can bypass ERC-4337 replay protection entirely, \
                                enabling double-spend of signed UserOperations.",
                                pc
                            ),
                            confidence: 0.88,
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
