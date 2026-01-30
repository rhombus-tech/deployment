use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Post080OverflowVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct IntegerOverflowPost080Detector {
    bytecode: Vec<u8>,
}

impl IntegerOverflowPost080Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<Post080OverflowVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unchecked_block_overflow());
        vulnerabilities.extend(self.detect_assembly_arithmetic_overflow());
        vulnerabilities.extend(self.detect_type_casting_overflow());

        vulnerabilities
    }

    fn detect_unchecked_block_overflow(&self) -> Vec<Post080OverflowVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0x01 | 0x02 | 0x03 | 0x04) { // ADD, MUL, SUB, DIV
                let start = if pc > 60 { pc - 60 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let window_end = (pc + 40).min(self.bytecode.len());
                let forward = &self.bytecode[pc..window_end];
                
                let has_overflow_check = forward.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT (Solidity 0.8 check)
                let has_revert = forward.iter().any(|&b| b == 0xFD); // REVERT
                
                if !has_overflow_check && !has_revert {
                    vulns.push(Post080OverflowVulnerability {
                        pc,
                        vulnerability_type: "UncheckedBlockOverflow".to_string(),
                        description: format!(
                            "Arithmetic at PC {} without overflow checks. Solidity 0.8+ adds automatic checks, but \
                            'unchecked {{}}' blocks bypass them for gas optimization. Historical vulnerability resurrection: \
                            developers using unchecked for performance without understanding overflow risks. Missing: explicit \
                            bounds validation, safe math library, overflow assertion. Post-0.8.0 contracts still vulnerable when \
                            using unchecked blocks incorrectly.",
                            pc
                        ),
                        confidence: 0.87,
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

    fn detect_assembly_arithmetic_overflow(&self) -> Vec<Post080OverflowVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut in_assembly_block = false;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x39 || opcode == 0x3A { // CODECOPY, GASPRICE (assembly markers)
                in_assembly_block = true;
            }

            if in_assembly_block && matches!(opcode, 0x01 | 0x02 | 0x03) { // ADD, MUL, SUB in assembly
                let start = if pc > 40 { pc - 40 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_manual_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11 | 0x14)); // Comparison ops
                
                if !has_manual_check {
                    vulns.push(Post080OverflowVulnerability {
                        pc,
                        vulnerability_type: "AssemblyArithmeticOverflow".to_string(),
                        description: format!(
                            "Assembly arithmetic at PC {} bypasses Solidity 0.8 overflow protection entirely. Inline assembly \
                            operations never receive automatic checks regardless of compiler version. Historical lesson ignored: \
                            developers assume 0.8+ = safe, forget assembly escapes safety net. Missing: manual overflow validation, \
                            assembly safety audit, bounds checking. Common in gas-optimized DeFi contracts.",
                            pc
                        ),
                        confidence: 0.90,
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

    fn detect_type_casting_overflow(&self) -> Vec<Post080OverflowVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x16 { // AND (type masking for downcasting)
                let start = if pc > 60 { pc - 60 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_mask = window.windows(2).any(|w| {
                    w[0] >= 0x60 && w[0] <= 0x7F && w[1] == 0xFF // PUSH + 0xFF (uint8 mask)
                });
                
                if has_mask {
                    let has_bounds_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if !has_bounds_check {
                        vulns.push(Post080OverflowVulnerability {
                            pc,
                            vulnerability_type: "TypeCastingOverflow".to_string(),
                            description: format!(
                                "Type downcast at PC {} silently truncates without overflow detection. Solidity 0.8 checks \
                                arithmetic but NOT type conversions (uint256→uint8). Historical vulnerability: developers assume \
                                all overflow protected, miss casting edge cases. Example: uint256(300) cast to uint8 becomes 44. \
                                Missing: pre-cast bounds validation, explicit range checks, safe casting library. \
                                Affects amount calculations, causing fund loss.",
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
