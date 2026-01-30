use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateRaceVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct StateMachineRaceConditionDetector {
    bytecode: Vec<u8>,
}

impl StateMachineRaceConditionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<StateRaceVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_check_state_use());
        vulnerabilities.extend(self.detect_multiple_state_updates());
        vulnerabilities.extend(self.detect_state_read_after_call());

        vulnerabilities
    }

    fn detect_check_state_use(&self) -> Vec<StateRaceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // SLOAD (reading state)
            if opcode == 0x54 {
                let window_end = (pc + 100).min(self.bytecode.len());
                let mut has_comparison = false;
                let mut has_external_call = false;
                let mut has_sstore = false;
                let mut has_lock = false;
                
                // Scan forward from SLOAD
                for check_pc in (pc + 1)..window_end {
                    let check_op = self.bytecode[check_pc];
                    
                    if check_op == 0x14 || check_op == 0x10 || check_op == 0x11 {
                        has_comparison = true;
                    }
                    if check_op == 0xF1 || check_op == 0xF4 { // CALL or DELEGATECALL
                        has_external_call = true;
                    }
                    if check_op == 0x55 { // SSTORE
                        has_sstore = true;
                        // Check for lock pattern (SSTORE before call)
                        if !has_external_call {
                            has_lock = true;
                        }
                    }
                }
                
                // TOCTOU: check state, external call, then use stale state
                if has_comparison && has_external_call && has_sstore && !has_lock {
                    vulns.push(StateRaceVulnerability {
                        pc,
                        vulnerability_type: "CheckStateUseRace".to_string(),
                        description: format!(
                            "TOCTOU race at PC {}: (1) SLOAD checks state, (2) External call allows reentrancy, \
                            (3) State used assuming original value. Attacker reenters and modifies state between \
                            check and use. Classic TOCTOU. Use checks-effects-interactions or reentrancy lock.",
                            pc
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

    fn detect_multiple_state_updates(&self) -> Vec<StateRaceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // First SSTORE
            if opcode == 0x55 {
                let window_end = (pc + 80).min(self.bytecode.len());
                let mut second_sstore_pc = None;
                let mut has_call_between = false;
                
                for check_pc in (pc + 1)..window_end {
                    if self.bytecode[check_pc] == 0xF1 || self.bytecode[check_pc] == 0xF4 {
                        has_call_between = true;
                    }
                    if self.bytecode[check_pc] == 0x55 {
                        second_sstore_pc = Some(check_pc);
                        break;
                    }
                }
                
                if let Some(sstore_pc) = second_sstore_pc {
                    if has_call_between {
                        vulns.push(StateRaceVulnerability {
                            pc,
                            vulnerability_type: "NonAtomicMultiUpdate".to_string(),
                            description: format!(
                                "Multiple state updates at PC {} and {} with external call between. State updates \
                                not atomic. Attacker can: (1) Reenter after first update, (2) See partial state, \
                                (3) Exploit inconsistency. Group state updates before external calls.",
                                pc, sstore_pc
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

    fn detect_state_read_after_call(&self) -> Vec<StateRaceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // External call
            if opcode == 0xF1 || opcode == 0xF4 {
                let window_end = (pc + 60).min(self.bytecode.len());
                let mut has_sload = false;
                let mut has_sstore = false;
                
                for check_pc in (pc + 1)..window_end {
                    if self.bytecode[check_pc] == 0x54 {
                        has_sload = true;
                    }
                    if self.bytecode[check_pc] == 0x55 {
                        has_sstore = true;
                        break;
                    }
                }
                
                if has_sload && has_sstore {
                    vulns.push(StateRaceVulnerability {
                        pc,
                        vulnerability_type: "StateReadAfterCall".to_string(),
                        description: format!(
                            "External call at PC {} followed by SLOAD then SSTORE. Reads potentially stale state \
                            after reentrancy opportunity. Attacker modifies state during call, then original \
                            execution uses modified value. Use state variables loaded before call or add reentrancy guard.",
                            pc
                        ),
                        confidence: 0.75,
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
