use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyInjectionVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct DependencyInjectionAttackDetector {
    bytecode: Vec<u8>,
}

impl DependencyInjectionAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<DependencyInjectionVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_malicious_dependency_substitution());
        vulnerabilities.extend(self.detect_dependency_address_manipulation());
        vulnerabilities.extend(self.detect_circular_dependency_exploit());

        vulnerabilities
    }

    fn detect_malicious_dependency_substitution(&self) -> Vec<DependencyInjectionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (setting dependency address)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_address_param = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_address_param {
                    let has_interface_check = window.iter().any(|&b| matches!(b, 0xFA | 0xF1)); // STATICCALL (supportsInterface)
                    let has_whitelist = window.iter().filter(|&&b| b == 0x14).count() >= 2; // Multiple EQ checks
                    let has_timelock = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    if !has_interface_check || !has_whitelist || !has_timelock {
                        vulns.push(DependencyInjectionVulnerability {
                            pc,
                            vulnerability_type: "MaliciousDependencySubstitution".to_string(),
                            description: format!(
                                "Dependency address update at PC {} without validation. Admin can inject malicious contract. Attack: \
                                replace oracle/token/router with attacker-controlled contract, drain funds or manipulate state. Missing: \
                                interface compliance check (EIP-165), address whitelist, timelock delay. Should verify new dependency \
                                implements expected interface and provide upgrade transparency.",
                                pc
                            ),
                            confidence: 0.90,
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

    fn detect_dependency_address_manipulation(&self) -> Vec<DependencyInjectionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (loading dependency address)
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_external_call = window.iter().any(|&b| matches!(b, 0xF1 | 0xF4)); // CALL, DELEGATECALL
                
                if has_external_call {
                    let start = if pc > 60 { pc - 60 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_validation = pre_window.iter().any(|&b| b == 0x15); // ISZERO (zero address check)
                    let has_initialization_check = pre_window.iter().any(|&b| b == 0x14); // EQ
                    
                    if !has_validation || !has_initialization_check {
                        vulns.push(DependencyInjectionVulnerability {
                            pc,
                            vulnerability_type: "DependencyAddressManipulation".to_string(),
                            description: format!(
                                "Dependency address loaded at PC {} and used without validation. Uninitialized or zero address causes \
                                unexpected behavior. Attack: trigger functionality before dependency set, call to zero address succeeds \
                                (no code), state corrupted. Missing: zero address check, initialization flag, default safe address. \
                                Should validate dependency exists before use.",
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

    fn detect_circular_dependency_exploit(&self) -> Vec<DependencyInjectionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF1 | 0xFA) { // External dependency call
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_dependency_addr = window.iter().any(|&b| b == 0x54); // SLOAD (dependency)
                
                if has_dependency_addr {
                    let has_reentrancy_guard = window.iter().any(|&b| b == 0x55); // SSTORE (setting guard)
                    let has_depth_limit = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT (max depth)
                    
                    if !has_reentrancy_guard && !has_depth_limit {
                        vulns.push(DependencyInjectionVulnerability {
                            pc,
                            vulnerability_type: "CircularDependencyExploit".to_string(),
                            description: format!(
                                "Dependency call at PC {} allows circular call chains. A→B→A→B creates infinite recursion or griefing. \
                                Attack: inject dependency that calls back into this contract, exhaust gas or manipulate state through \
                                repeated execution. Missing: reentrancy guard, call depth tracking, circular dependency detection. \
                                Should prevent or limit recursive cross-contract calls.",
                                pc
                            ),
                            confidence: 0.84,
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
