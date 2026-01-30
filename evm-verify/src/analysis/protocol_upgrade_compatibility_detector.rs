use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolUpgradeVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ProtocolUpgradeCompatibilityDetector {
    bytecode: Vec<u8>,
}

impl ProtocolUpgradeCompatibilityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ProtocolUpgradeVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_storage_collision_on_upgrade());
        vulnerabilities.extend(self.detect_incompatible_interface_change());
        vulnerabilities.extend(self.detect_initialization_reentrancy());

        vulnerabilities
    }

    fn detect_storage_collision_on_upgrade(&self) -> Vec<ProtocolUpgradeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (storage write)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_storage_slot = window.iter().any(|&b| matches!(b, 0x60..=0x7F)); // PUSH (slot number)
                
                if has_storage_slot {
                    let has_namespace = window.iter().any(|&b| b == 0x20); // KECCAK256 (namespaced storage)
                    let has_version_check = window.iter().any(|&b| b == 0x54); // SLOAD (version validation)
                    
                    if !has_namespace && !has_version_check {
                        vulns.push(ProtocolUpgradeVulnerability {
                            pc,
                            vulnerability_type: "StorageCollisionOnUpgrade".to_string(),
                            description: format!(
                                "Storage write at PC {} uses sequential slots without namespace protection. Proxy upgrade adding new \
                                variables can collide with existing storage. Attack: upgrade shifts storage layout, overwrites critical \
                                state like owner address or balances. Missing: EIP-1967 namespaced storage, storage gap pattern, \
                                append-only upgrades. Should use keccak256(\"namespace\") - 1 for upgrade-safe storage.",
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

    fn detect_incompatible_interface_change(&self) -> Vec<ProtocolUpgradeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF1 | 0xFA) { // External protocol call
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_function_selector = window.windows(2).any(|w| w[0] >= 0x60 && w[0] <= 0x7F); // PUSH4 selector
                
                if has_function_selector {
                    let has_version_check = window.iter().any(|&b| b == 0x54); // SLOAD (version)
                    let has_fallback = window.iter().filter(|&&b| b == 0x57).count() >= 2; // Multiple JUMPI
                    
                    if !has_version_check && !has_fallback {
                        vulns.push(ProtocolUpgradeVulnerability {
                            pc,
                            vulnerability_type: "IncompatibleInterfaceChange".to_string(),
                            description: format!(
                                "External call at PC {} assumes fixed interface without version check. Protocol upgrade changing function \
                                signature/behavior causes failure. Attack: integrated protocol upgrades, removes function, changes return \
                                type, this contract breaks. Missing: interface version validation, graceful degradation, try-catch pattern. \
                                Should verify protocol version compatibility before integration.",
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

    fn detect_initialization_reentrancy(&self) -> Vec<ProtocolUpgradeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (initialization flag)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_initialization = window.iter().any(|&b| b == 0x35); // CALLDATALOAD (init params)
                
                if has_initialization {
                    let has_initialized_check = window.iter().any(|&b| b == 0x54); // SLOAD (checking flag)
                    let has_external_call_before = window.iter().any(|&b| matches!(b, 0xF1 | 0xF4)); // CALL before flag set
                    
                    if has_initialized_check && has_external_call_before {
                        let window_end = (pc + 60).min(self.bytecode.len());
                        let forward = &self.bytecode[pc..window_end];
                        
                        let flag_set_after_calls = !forward.iter().any(|&b| matches!(b, 0xF1 | 0xF4));
                        
                        if !flag_set_after_calls {
                            vulns.push(ProtocolUpgradeVulnerability {
                                pc,
                                vulnerability_type: "InitializationReentrancy".to_string(),
                                description: format!(
                                    "Initialization at PC {} sets initialized flag after external calls. Reentrancy during initialization \
                                    allows re-initialization. Attack: malicious contract called during init, reenters initialize(), runs \
                                    twice, resets owner/config. Missing: initialized flag set BEFORE external calls, reentrancy guard on \
                                    initialize(). Initialization should follow checks-effects-interactions pattern.",
                                    pc
                                ),
                                confidence: 0.89,
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
