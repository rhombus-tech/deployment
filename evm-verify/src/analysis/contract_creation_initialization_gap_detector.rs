use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializationGapVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ContractCreationInitializationGapDetector {
    bytecode: Vec<u8>,
}

impl ContractCreationInitializationGapDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<InitializationGapVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_create2_frontrun_initialize());
        vulnerabilities.extend(self.detect_constructor_state_race());
        vulnerabilities.extend(self.detect_uninitialized_implementation_call());

        vulnerabilities
    }

    fn detect_create2_frontrun_initialize(&self) -> Vec<InitializationGapVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF5 { // CREATE2
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_initialize_call = window.iter().any(|&b| matches!(b, 0xF1 | 0xFA)); // CALL, STATICCALL
                
                if has_initialize_call {
                    let has_atomic_check = window.iter().filter(|&&b| b == 0x57).count() >= 3; // Multiple conditional jumps
                    let has_success_validation = window.iter().any(|&b| b == 0x15); // ISZERO
                    
                    if !has_atomic_check {
                        vulns.push(InitializationGapVulnerability {
                            pc,
                            vulnerability_type: "Create2FrontrunInitialize".to_string(),
                            description: format!(
                                "CREATE2 at PC {} followed by separate initialize() call. Window between deployment and initialization \
                                allows frontrunning. Attack: observe CREATE2 tx in mempool, calculate deterministic address, frontrun \
                                with own initialize() call, gain ownership of newly deployed contract. Missing: initialization in \
                                constructor, atomic deployment + init in single tx, CREATE2 with init data in bytecode. Should deploy \
                                with initialization parameters in constructor or use initializer modifier that prevents re-init.",
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

    fn detect_constructor_state_race(&self) -> Vec<InitializationGapVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF0 | 0xF5) { // CREATE, CREATE2
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_init_code = window.iter().any(|&b| b == 0x39); // CODECOPY (init code)
                
                if has_init_code {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_state_dependency = forward.iter().any(|&b| matches!(b, 0xF1 | 0xFA)); // External call
                    let has_event_emission = forward.iter().any(|&b| matches!(b, 0xA0..=0xA4)); // LOG
                    
                    if has_state_dependency {
                        let has_success_check = forward.iter().any(|&b| b == 0x15); // ISZERO
                        
                        if !has_success_check {
                            vulns.push(InitializationGapVulnerability {
                                pc,
                                vulnerability_type: "ConstructorStateRace".to_string(),
                                description: format!(
                                    "Contract creation at PC {} with constructor making external calls before setting initialized state. \
                                    Constructor reentrancy allows calls to uninitialized contract. Attack: called contract reenters new \
                                    contract's public functions before constructor completes, state variables uninitialized, default \
                                    values exploitable. Missing: initialized flag set before external calls, constructor-only functions, \
                                    reentrancy guard. Constructor should complete state setup before any external interaction.",
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

    fn detect_uninitialized_implementation_call(&self) -> Vec<InitializationGapVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF4 { // DELEGATECALL (proxy pattern)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_implementation_load = window.iter().any(|&b| b == 0x54); // SLOAD
                
                if has_implementation_load {
                    let has_zero_check = window.iter().any(|&b| b == 0x15); // ISZERO
                    let has_revert = window.iter().any(|&b| b == 0xFD); // REVERT
                    
                    if !has_zero_check || !has_revert {
                        vulns.push(InitializationGapVulnerability {
                            pc,
                            vulnerability_type: "UninitializedImplementationCall".to_string(),
                            description: format!(
                                "DELEGATECALL at PC {} to potentially uninitialized implementation address. Proxy deployed but \
                                implementation not set yet allows delegatecall to zero address or unintended contract. Attack: \
                                interact with proxy before setImplementation() called, delegatecall to address(0) or default value, \
                                unexpected behavior. Missing: zero address validation, initialization check before delegatecall, \
                                implementation set in constructor. Proxy should revert if implementation == address(0).",
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
