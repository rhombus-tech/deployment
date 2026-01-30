use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MoveVmResourceVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct MoveVmResourceSafetyBypassDetector {
    bytecode: Vec<u8>,
}

impl MoveVmResourceSafetyBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<MoveVmResourceVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_linear_type_duplication());
        vulnerabilities.extend(self.detect_resource_destruction_bypass());
        vulnerabilities.extend(self.detect_global_storage_aliasing());

        vulnerabilities
    }

    fn detect_linear_type_duplication(&self) -> Vec<MoveVmResourceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0x80..=0x8F) { // DUP1-DUP16
                let start = if pc > 60 { pc - 60 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_external_call = window.iter().any(|&b| matches!(b, 0xF1 | 0xF4 | 0xFA)); // CALL variants
                let has_storage_op = window.iter().any(|&b| matches!(b, 0x54 | 0x55)); // SLOAD, SSTORE
                
                if has_external_call || has_storage_op {
                    vulns.push(MoveVmResourceVulnerability {
                        pc,
                        vulnerability_type: "LinearTypeDuplication".to_string(),
                        description: format!(
                            "Stack duplication at PC {} violates Move VM linear type safety. Move resources have \
                            'copy' restrictions preventing duplication, enforcing single ownership. EVM DUP allows \
                            duplicating references to same resource, enabling: (1) double-spend of assets, \
                            (2) resource cloning, (3) violation of uniqueness invariants. When bridging EVM→Move, \
                            duplicated values treated as separate resources. Missing: linear type tracking, \
                            move-only semantics, resource uniqueness enforcement.",
                            pc
                        ),
                        confidence: 0.88,
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

    fn detect_resource_destruction_bypass(&self) -> Vec<MoveVmResourceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x50 { // POP
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_sload = window.iter().any(|&b| b == 0x54); // SLOAD (loading resource)
                let has_call = window.iter().any(|&b| matches!(b, 0xF1 | 0xF4)); // External call
                
                if has_sload || has_call {
                    let window_end = (pc + 40).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_destructor = forward.iter().any(|&b| matches!(b, 0x55 | 0xF1)); // SSTORE or CALL
                    
                    if !has_destructor {
                        vulns.push(MoveVmResourceVulnerability {
                            pc,
                            vulnerability_type: "ResourceDestructionBypass".to_string(),
                            description: format!(
                                "Resource value discarded via POP at PC {} without proper destruction. Move VM enforces \
                                explicit resource destruction via 'drop' capability or transfer to global storage. \
                                Simply popping resource value from stack: (1) leaks resource permanently, (2) breaks \
                                resource accounting, (3) violates conservation laws. Missing: explicit destructor call, \
                                transfer to storage, capability check. Enables resource leakage and supply inflation.",
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

    fn detect_global_storage_aliasing(&self) -> Vec<MoveVmResourceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD
                let start = if pc > 60 { pc - 60 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_dynamic_key = window.iter().any(|&b| matches!(b, 0x01 | 0x02 | 0x20)); // ADD, MUL, KECCAK256
                
                if has_dynamic_key {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let sload_count = forward.iter().filter(|&&b| b == 0x54).count();
                    
                    if sload_count >= 2 {
                        vulns.push(MoveVmResourceVulnerability {
                            pc,
                            vulnerability_type: "GlobalStorageAliasing".to_string(),
                            description: format!(
                                "Multiple SLOAD operations at PC {} enable storage aliasing forbidden in Move VM. \
                                Move's global storage has strict access rules: resources at address can only be accessed \
                                once per transaction, preventing aliasing. EVM allows multiple reads/writes to same storage, \
                                enabling: (1) borrow checker bypass, (2) concurrent mutable access, (3) reentrancy via storage. \
                                Missing: storage access uniqueness tracking, borrow checker, exclusive access enforcement. \
                                Incompatible with Move's memory safety guarantees.",
                                pc
                            ),
                            confidence: 0.83,
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
