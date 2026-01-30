use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateMachineDeadlockVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct StateMachineDeadlockDetector {
    bytecode: Vec<u8>,
}

impl StateMachineDeadlockDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<StateMachineDeadlockVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_mutually_exclusive_conditions());
        vulnerabilities.extend(self.detect_impossible_state_requirements());
        vulnerabilities.extend(self.detect_unrecoverable_states());

        vulnerabilities
    }

    fn detect_mutually_exclusive_conditions(&self) -> Vec<StateMachineDeadlockVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for state transitions requiring multiple conditions
            if opcode == 0x55 { // SSTORE (state change)
                let start = if pc > 100 { pc - 100 } else { 0 };
                
                // Count SLOAD operations (checking multiple state variables)
                let sload_count = self.bytecode[start..pc].iter().filter(|&&b| b == 0x54).count();
                
                // Count EQ comparisons (checking conditions)
                let eq_count = self.bytecode[start..pc].iter().filter(|&&b| b == 0x14).count();
                
                // Count ISZERO operations (NOT logic)
                let not_count = self.bytecode[start..pc].iter().filter(|&&b| b == 0x15).count();
                
                // Multiple state checks with negations suggest mutually exclusive conditions
                if sload_count >= 3 && eq_count >= 2 && not_count >= 1 {
                    vulns.push(StateMachineDeadlockVulnerability {
                        pc,
                        vulnerability_type: "MutuallyExclusiveConditions".to_string(),
                        description: format!(
                            "State transition at PC {} requires {} state checks with negations. \
                            Conditions may be mutually exclusive: state A requires B=true AND C=false, \
                            but B can only be true if C=true. Creates deadlock where transition is impossible. \
                            Verify state transition conditions are satisfiable.",
                            pc, sload_count
                        ),
                        confidence: 0.70,
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

    fn detect_impossible_state_requirements(&self) -> Vec<StateMachineDeadlockVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // State transition (SSTORE)
            if opcode == 0x55 {
                let start = if pc > 80 { pc - 80 } else { 0 };
                
                // Check for AND operation after multiple SLOADs (requires all conditions)
                let has_sload = self.bytecode[start..pc].iter().any(|&b| b == 0x54);
                let and_count = self.bytecode[start..pc].iter().filter(|&&b| b == 0x16).count(); // AND opcode
                
                // Multiple ANDs with REVERT suggests strict requirements
                let window_end = (pc + 30).min(self.bytecode.len());
                let has_revert = self.bytecode[(pc + 1)..window_end].iter().any(|&b| b == 0xFD);
                
                if has_sload && and_count >= 2 && has_revert {
                    vulns.push(StateMachineDeadlockVulnerability {
                        pc,
                        vulnerability_type: "ImpossibleRequirements".to_string(),
                        description: format!(
                            "State update at PC {} requires multiple AND conditions. Risk: state can only \
                            be set if condition1 AND condition2 AND condition3 all true, but these conditions \
                            may never be simultaneously satisfiable. Example: require(paused && !paused) is impossible. \
                            Review boolean logic for satisfiability.",
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

    fn detect_unrecoverable_states(&self) -> Vec<StateMachineDeadlockVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // SSTORE setting state
            if opcode == 0x55 {
                let start = if pc > 60 { pc - 60 } else { 0 };
                
                // Check if state value is constant (PUSH)
                let mut has_constant_state = false;
                let mut temp_pc = start;
                while temp_pc < pc {
                    if self.bytecode[temp_pc] >= 0x60 && self.bytecode[temp_pc] <= 0x7F {
                        has_constant_state = true;
                        break;
                    }
                    temp_pc += 1;
                }
                
                if has_constant_state {
                    // Check if there's a way to exit this state (look for SSTORE to same slot later)
                    let same_slot_updates = self.bytecode[(pc + 1)..].windows(20)
                        .filter(|w| w.iter().any(|&b| b == 0x55))
                        .count();
                    
                    if same_slot_updates == 0 {
                        vulns.push(StateMachineDeadlockVulnerability {
                            pc,
                            vulnerability_type: "UnrecoverableState".to_string(),
                            description: format!(
                                "State set at PC {} appears permanent with no recovery path. Once entered, \
                                state cannot be changed. Creates: (1) Stuck contracts, (2) Permanently paused systems, \
                                (3) Bricked functionality. Add admin override or time-based recovery mechanism.",
                                pc
                            ),
                            confidence: 0.65,
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
