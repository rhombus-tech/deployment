use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolAssumptionVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ExternalProtocolAssumptionViolationDetector {
    bytecode: Vec<u8>,
}

impl ExternalProtocolAssumptionViolationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ProtocolAssumptionVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unchecked_protocol_invariants());
        vulnerabilities.extend(self.detect_protocol_pause_assumption());
        vulnerabilities.extend(self.detect_protocol_upgrade_incompatibility());

        vulnerabilities
    }

    fn detect_unchecked_protocol_invariants(&self) -> Vec<ProtocolAssumptionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xFA | 0xF1) { // External protocol call
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_function_call = window.windows(2).any(|w| w[0] >= 0x60 && w[0] <= 0x7F); // PUSH selector
                
                if has_function_call {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_return_validation = forward.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_revert_check = forward.iter().any(|&b| b == 0x15); // ISZERO (success check)
                    
                    if has_return_validation && has_revert_check {
                        let has_invariant_check = forward.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                        
                        if !has_invariant_check {
                            vulns.push(ProtocolAssumptionVulnerability {
                                pc,
                                vulnerability_type: "UncheckedProtocolInvariants".to_string(),
                                description: format!(
                                    "External protocol call at PC {} validates success but not invariants. Assumes external protocol \
                                    behaves correctly. Attack: malicious/buggy protocol returns success but violates invariants (e.g., \
                                    returns 0 tokens, wrong price). Missing: range validation on return values, sanity checks on state \
                                    changes, invariant verification. Should never trust external protocol's correctness.",
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

    fn detect_protocol_pause_assumption(&self) -> Vec<ProtocolAssumptionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF1 | 0xFA) { // Protocol interaction
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_protocol_addr = window.iter().any(|&b| b == 0x54); // SLOAD (dependency)
                
                if has_protocol_addr {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_pause_check = window.iter().any(|&b| matches!(b, 0xFA | 0xF1)); // Calling isPaused()
                    let has_fallback_logic = forward.iter().filter(|&&b| b == 0x57).count() >= 2;
                    
                    if !has_pause_check && !has_fallback_logic {
                        vulns.push(ProtocolAssumptionVulnerability {
                            pc,
                            vulnerability_type: "ProtocolPauseAssumption".to_string(),
                            description: format!(
                                "Protocol interaction at PC {} assumes availability. External protocol can pause, causing this contract \
                                to fail. Attack: integrated protocol pauses (emergency or malicious), this contract cannot function, \
                                funds locked. Missing: pause state check before calls, fallback to alternative protocol, graceful \
                                degradation. Should handle external protocol unavailability.",
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

    fn detect_protocol_upgrade_incompatibility(&self) -> Vec<ProtocolAssumptionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF1 | 0xFA) { // External call
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_selector = window.windows(2).any(|w| w[0] >= 0x60 && w[0] <= 0x63); // PUSH4 (function selector)
                
                if has_selector {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_success_check = forward.iter().any(|&b| b == 0x15); // ISZERO
                    
                    if has_success_check {
                        let has_try_catch = forward.iter().filter(|&&b| b == 0x57).count() >= 3; // Multiple paths
                        let has_version_check = window.iter().any(|&b| b == 0x54); // SLOAD (version)
                        
                        if !has_try_catch && !has_version_check {
                            vulns.push(ProtocolAssumptionVulnerability {
                                pc,
                                vulnerability_type: "ProtocolUpgradeIncompatibility".to_string(),
                                description: format!(
                                    "External call at PC {} assumes fixed protocol interface. Protocol upgrades changing function \
                                    signature cause revert, locking functionality. Attack: integrated protocol upgrades, removes/changes \
                                    function, all calls fail, contract bricked. Missing: try-catch pattern, interface version tracking, \
                                    multiple integration paths. Should handle protocol evolution gracefully.",
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
}
