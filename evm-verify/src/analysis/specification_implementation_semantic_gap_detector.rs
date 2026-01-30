use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticGapVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct SpecificationImplementationSemanticGapDetector {
    bytecode: Vec<u8>,
}

impl SpecificationImplementationSemanticGapDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SemanticGapVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_erc_standard_violation());
        vulnerabilities.extend(self.detect_natspec_implementation_mismatch());
        vulnerabilities.extend(self.detect_function_selector_shadowing());

        vulnerabilities
    }

    fn detect_erc_standard_violation(&self) -> Vec<SemanticGapVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x00 { // STOP (function return)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Check for transfer function pattern (ERC20)
                let has_transfer_selector = window.windows(4).any(|w| {
                    w == [0x60, 0xa9, 0x05, 0x9c] || // transfer(address,uint256)
                    w == [0x60, 0x23, 0xb8, 0x72]    // transferFrom(address,address,uint256)
                });
                
                if has_transfer_selector {
                    let has_return_value = window.iter().any(|&b| b == 0xF3); // RETURN
                    let has_boolean_push = window.windows(2).any(|w| w[0] == 0x60 && (w[1] == 0x00 || w[1] == 0x01));
                    
                    if !has_return_value || !has_boolean_push {
                        vulns.push(SemanticGapVulnerability {
                            pc,
                            vulnerability_type: "ERCStandardViolation".to_string(),
                            description: format!(
                                "ERC20 transfer at PC {} doesn't return boolean per EIP-20 specification. Spec requires: 'Returns: \
                                success (bool)'. Implementation uses STOP instead of RETURN with true/false. Attack: integrations \
                                expecting return value (OpenZeppelin SafeERC20) will revert, breaking composability. Users can't \
                                distinguish success from failure. Missing: RETURN opcode with 0x01 (true) or 0x00 (false). Must \
                                return bool to match specification and enable safe integrations.",
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

    fn detect_natspec_implementation_mismatch(&self) -> Vec<SemanticGapVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xFD { // REVERT
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                // Function with access control check
                let has_access_check = window.iter().any(|&b| matches!(b, 0x33 | 0x32)); // CALLER, ORIGIN
                let has_comparison = window.iter().any(|&b| b == 0x14); // EQ
                
                if has_access_check && has_comparison {
                    let has_revert_reason = window.iter().any(|&b| b == 0x08); // ADDMOD (string operations)
                    let has_error_selector = window.windows(4).any(|w| w[0] == 0x60);
                    
                    if !has_revert_reason && !has_error_selector {
                        vulns.push(SemanticGapVulnerability {
                            pc,
                            vulnerability_type: "NatspecImplementationMismatch".to_string(),
                            description: format!(
                                "Access control revert at PC {} provides no error message despite NatSpec documentation. \
                                Documentation promises '@notice Only owner can call' but implementation reverts silently. Users \
                                can't distinguish between: onlyOwner failure, input validation failure, business logic failure. \
                                Attack: confusion about rejection reason enables social engineering, phishing. Missing: custom \
                                error with selector, revert reason string matching documentation. Should emit 'Unauthorized()' or \
                                revert('Only owner') matching NatSpec description.",
                                pc
                            ),
                            confidence: 0.82,
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

    fn detect_function_selector_shadowing(&self) -> Vec<SemanticGapVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut seen_selectors = std::collections::HashSet::new();

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for function selector checks (PUSH4 followed by EQ)
            if opcode == 0x63 && pc + 4 < self.bytecode.len() {
                let selector = [
                    self.bytecode[pc + 1],
                    self.bytecode[pc + 2],
                    self.bytecode[pc + 3],
                    self.bytecode[pc + 4],
                ];
                
                let selector_u32 = u32::from_be_bytes(selector);
                
                if !seen_selectors.insert(selector_u32) {
                    // Duplicate selector found
                    vulns.push(SemanticGapVulnerability {
                        pc,
                        vulnerability_type: "FunctionSelectorShadowing".to_string(),
                        description: format!(
                            "Duplicate function selector 0x{:08x} at PC {}. Either: (1) same function name in parent and child \
                            contract, child shadows parent, or (2) hash collision where func1() and func2() have same 4-byte selector. \
                            Attack: call to func1() actually executes func2(), breaking assumptions. Specification says one function, \
                            implementation provides another. Missing: unique selectors across inheritance, collision detection. Should \
                            rename functions to ensure unique selectors or use diamond pattern facet dispatch.",
                            selector_u32, pc
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
}
