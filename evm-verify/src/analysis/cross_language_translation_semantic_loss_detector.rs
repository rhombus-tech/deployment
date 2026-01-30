use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranslationSemanticLossVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CrossLanguageTranslationSemanticLossDetector {
    bytecode: Vec<u8>,
}

impl CrossLanguageTranslationSemanticLossDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<TranslationSemanticLossVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_vyper_safe_math_assumption());
        vulnerabilities.extend(self.detect_yul_inline_assembly_unchecked());
        vulnerabilities.extend(self.detect_solidity_version_behavior_change());

        vulnerabilities
    }

    fn detect_vyper_safe_math_assumption(&self) -> Vec<TranslationSemanticLossVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0x01 | 0x02 | 0x03 | 0x04) { // ADD, MUL, SUB, DIV
                let window_end = (pc + 30).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check if overflow check is present (Vyper pattern)
                let has_overflow_check = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                let has_revert = window.iter().any(|&b| b == 0xFD); // REVERT
                
                if !has_overflow_check || !has_revert {
                    // Likely Solidity unchecked block or pre-0.8.0
                    let start = if pc > 50 { pc - 50 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_large_values = pre_window.windows(5).any(|w| {
                        w[0] >= 0x62 && w[0] <= 0x7F // PUSH3 or larger
                    });
                    
                    if has_large_values {
                        vulns.push(TranslationSemanticLossVulnerability {
                            pc,
                            vulnerability_type: "VyperSafeMathAssumption".to_string(),
                            description: format!(
                                "Arithmetic at PC {} lacks overflow checks, differs from Vyper assumption. Vyper automatically includes \
                                overflow checks, Solidity <0.8.0 or unchecked blocks do not. Attack: port Vyper contract to Solidity, \
                                assume safety from overflow, arithmetic wraps instead of reverting, unexpected state. Spec: 'addition is \
                                safe', implementation: wrapping addition. Missing: require() checks or SafeMath, Solidity 0.8+ checked \
                                arithmetic. Translation loses Vyper's automatic safety guarantees.",
                                pc
                            ),
                            confidence: 0.80,
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

    fn detect_yul_inline_assembly_unchecked(&self) -> Vec<TranslationSemanticLossVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Detect inline assembly patterns (direct storage manipulation)
            if opcode == 0x55 { // SSTORE
                let start = if pc > 60 { pc - 60 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for direct CALLDATALOAD -> SSTORE (assembly pattern)
                let has_direct_calldata = window.iter().rev().take(10).any(|&b| b == 0x35);
                let has_no_validation = !window.iter().any(|&b| matches!(b, 0x10 | 0x11 | 0x14)); // No comparisons
                
                if has_direct_calldata && has_no_validation {
                    vulns.push(TranslationSemanticLossVulnerability {
                        pc,
                        vulnerability_type: "YulInlineAssemblyUnchecked".to_string(),
                        description: format!(
                            "Storage write at PC {} bypasses Solidity type checks via assembly. High-level code: 'function setOwner(address \
                            owner) {{ owner = owner; }}' with type safety. Assembly translation: 'assembly {{ sstore(slot, calldataload(4)) }}' \
                            loses type checking. Attack: pass non-address value, assembly accepts any 32 bytes, storage corrupted. Spec expects \
                            address type, implementation accepts any bytes32. Missing: explicit type validation in assembly blocks. Should \
                            validate inputs before assembly storage writes.",
                            pc
                        ),
                        confidence: 0.83,
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

    fn detect_solidity_version_behavior_change(&self) -> Vec<TranslationSemanticLossVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Detect ABI encoding patterns that changed between versions
            if opcode == 0x20 { // KECCAK256 (ABI encoding)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_dynamic_array = window.iter().filter(|&&b| b == 0x52).count() >= 2; // Multiple MSTORE
                let has_encoding_logic = window.iter().any(|&b| matches!(b, 0x01 | 0x02)); // ADD, MUL
                
                if has_dynamic_array && has_encoding_logic {
                    let has_abi_version_check = window.iter().any(|&b| b == 0x3A); // GASPRICE (version flag)
                    
                    if !has_abi_version_check {
                        vulns.push(TranslationSemanticLossVulnerability {
                            pc,
                            vulnerability_type: "SolidityVersionBehaviorChange".to_string(),
                            description: format!(
                                "ABI encoding at PC {} without version-specific handling. Solidity 0.5.0 changed packed encoding, 0.8.0 \
                                changed default ABI coder. Contract compiled with 0.4.x and interacting with 0.8.x uses different encoding. \
                                Attack: sig := keccak256(abi.encode(...)) produces different hash across versions, signature verification fails \
                                or succeeds unexpectedly. Spec assumes one encoding, implementation varies by compiler version. Missing: explicit \
                                ABIEncoderV2 or packed mode specification. Should lock ABI encoding behavior explicitly.",
                                pc
                            ),
                            confidence: 0.78,
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
