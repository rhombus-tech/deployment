use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReentrancyEvolutionVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ReentrancyVariantEvolutionDetector {
    bytecode: Vec<u8>,
}

impl ReentrancyVariantEvolutionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ReentrancyEvolutionVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_cross_function_reentrancy());
        vulnerabilities.extend(self.detect_cross_contract_reentrancy_loop());
        vulnerabilities.extend(self.detect_delegatecall_reentrancy());

        vulnerabilities
    }

    fn detect_cross_function_reentrancy(&self) -> Vec<ReentrancyEvolutionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF1 | 0xF4) { // CALL, DELEGATECALL
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_sstore = window.iter().any(|&b| b == 0x55); // State change after call
                
                if has_sstore {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_function_selector = pre_window.windows(2).any(|w| {
                        w[0] == 0x60 && w[1] == 0xE0 // PUSH1 0xE0 (function selector extraction)
                    });
                    
                    if has_function_selector {
                        let has_reentrancy_guard = pre_window.windows(2).any(|w| {
                            w[0] == 0x54 && w[1] == 0x15 // SLOAD + ISZERO (checking lock)
                        });
                        
                        if !has_reentrancy_guard {
                            vulns.push(ReentrancyEvolutionVulnerability {
                                pc,
                                vulnerability_type: "CrossFunctionReentrancy".to_string(),
                                description: format!(
                                    "Cross-function reentrancy at PC {}. Modern variant: attacker reenters different function \
                                    than original, bypassing function-specific guards. Example: withdraw() calls malicious contract, \
                                    which reenters via deposit(), exploiting shared state. Single-function guards inadequate. \
                                    Missing: contract-wide reentrancy lock, global mutex, comprehensive state tracking. \
                                    Evolution from classic single-function reentrancy (DAO hack 2016).",
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

    fn detect_cross_contract_reentrancy_loop(&self) -> Vec<ReentrancyEvolutionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF1 | 0xF4 | 0xFA) { // External calls
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_address_param = window.iter().any(|&b| b == 0x35); // CALLDATALOAD (target address)
                
                if has_address_param {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_state_read = forward.iter().any(|&b| b == 0x54); // SLOAD
                    let has_state_write = forward.iter().any(|&b| b == 0x55); // SSTORE
                    
                    if has_state_read && has_state_write {
                        let has_address_whitelist = window.iter().any(|&b| b == 0x14); // EQ (address check)
                        
                        if !has_address_whitelist {
                            vulns.push(ReentrancyEvolutionVulnerability {
                                pc,
                                vulnerability_type: "CrossContractReentrancyLoop".to_string(),
                                description: format!(
                                    "Cross-contract reentrancy loop at PC {}. Advanced attack: A→B→C→A where each contract \
                                    appears safe individually but loop exploits shared state. Example: Lending protocol calls \
                                    collateral oracle, which calls price feed, which reenters lending. Missing: call depth tracking, \
                                    inter-contract reentrancy detection, address chain validation. Evolution beyond single contract scope.",
                                    pc
                                ),
                                confidence: 0.86,
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

    fn detect_delegatecall_reentrancy(&self) -> Vec<ReentrancyEvolutionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF4 { // DELEGATECALL
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_implementation = window.iter().any(|&b| b == 0x54); // SLOAD (implementation address)
                
                if has_implementation {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_storage_write = forward.iter().any(|&b| b == 0x55); // SSTORE
                    
                    if has_storage_write {
                        let has_delegatecall_guard = window.windows(3).any(|w| {
                            w[0] == 0x54 && w[1] == 0x15 && w[2] == 0x57 // SLOAD + ISZERO + JUMPI
                        });
                        
                        if !has_delegatecall_guard {
                            vulns.push(ReentrancyEvolutionVulnerability {
                                pc,
                                vulnerability_type: "DelegatecallReentrancy".to_string(),
                                description: format!(
                                    "DELEGATECALL reentrancy at PC {} - modern proxy pattern vulnerability. Attack: malicious \
                                    implementation uses DELEGATECALL to reenter proxy with attacker's context, manipulating proxy \
                                    storage. Example: Parity wallet hack 2017. Implementation can call back to proxy, executing with \
                                    proxy's storage but implementation's code. Missing: DELEGATECALL-specific guard, implementation \
                                    trust verification, storage isolation. Evolution: exploits upgradeable contract patterns.",
                                    pc
                                ),
                                confidence: 0.91,
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
