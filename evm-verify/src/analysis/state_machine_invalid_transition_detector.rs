use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidTransitionVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct StateMachineInvalidTransitionDetector {
    bytecode: Vec<u8>,
}

impl StateMachineInvalidTransitionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<InvalidTransitionVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unchecked_state_changes());
        vulnerabilities.extend(self.detect_missing_state_validation());
        vulnerabilities.extend(self.detect_direct_state_overwrites());

        vulnerabilities
    }

    fn detect_unchecked_state_changes(&self) -> Vec<InvalidTransitionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            if opcode == 0x55 { // SSTORE (state change)
                let start = if pc > 80 { pc - 80 } else { 0 };
                
                // Check if current state is loaded and validated
                let has_sload = self.bytecode[start..pc].iter().any(|&b| b == 0x54);
                let has_comparison = self.bytecode[start..pc].iter().any(|&b| b == 0x14 || b == 0x10 || b == 0x11);
                
                // State change without reading current state is suspicious
                if !has_sload || !has_comparison {
                    vulns.push(InvalidTransitionVulnerability {
                        pc,
                        vulnerability_type: "UncheckedStateChange".to_string(),
                        description: format!(
                            "State modified at PC {} without validating current state. Allows invalid transitions: \
                            can jump from state A directly to state C, skipping required state B. Example: \
                            contract can be finalized without being initialized. Validate current state before transition.",
                            pc
                        ),
                        confidence: 0.80,
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

    fn detect_missing_state_validation(&self) -> Vec<InvalidTransitionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            if opcode == 0x55 { // SSTORE
                let start = if pc > 100 { pc - 100 } else { 0 };
                
                // Check for state loading
                let sload_count = self.bytecode[start..pc].iter().filter(|&&b| b == 0x54).count();
                
                // Check for validation jumps (JUMPI means conditional logic)
                let has_jumpi = self.bytecode[start..pc].iter().any(|&b| b == 0x57);
                
                // Loading state but no conditional jump means no validation
                if sload_count >= 1 && !has_jumpi {
                    vulns.push(InvalidTransitionVulnerability {
                        pc,
                        vulnerability_type: "MissingTransitionValidation".to_string(),
                        description: format!(
                            "State change at PC {} loads current state but doesn't validate transition. \
                            State is read but not checked for valid transition path. Attacker can trigger \
                            transitions that should be forbidden (e.g., Paused -> Active without Initialized). \
                            Add require() to validate allowed transitions.",
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

    fn detect_direct_state_overwrites(&self) -> Vec<InvalidTransitionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            if opcode == 0x55 { // SSTORE
                let start = if pc > 50 { pc - 50 } else { 0 };
                
                // Check if value comes directly from calldata (user input)
                let has_calldataload = self.bytecode[start..pc].iter().any(|&b| b == 0x35);
                
                // Check for access control (CALLER comparison)
                let has_caller_check = self.bytecode[start..pc].iter().any(|&b| b == 0x33);
                let has_eq_check = self.bytecode[start..pc].iter().any(|&b| b == 0x14);
                
                if has_calldataload && !(has_caller_check && has_eq_check) {
                    vulns.push(InvalidTransitionVulnerability {
                        pc,
                        vulnerability_type: "DirectStateOverwrite".to_string(),
                        description: format!(
                            "State directly overwritten from calldata at PC {} without access control or validation. \
                            Anyone can set arbitrary state value. Bypasses: (1) State machine logic, \
                            (2) Transition rules, (3) Business logic invariants. Add owner check and state validation.",
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
}
