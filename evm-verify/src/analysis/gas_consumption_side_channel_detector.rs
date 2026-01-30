use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasLeakage {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct GasConsumptionSideChannelDetector {
    bytecode: Vec<u8>,
}

impl GasConsumptionSideChannelDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<GasLeakage> {
        let mut vulnerabilities = Vec::new();

        // Detect data-dependent loops (gas varies with secret data)
        vulnerabilities.extend(self.detect_data_dependent_loops());
        
        // Detect conditional expensive operations
        vulnerabilities.extend(self.detect_conditional_crypto());
        
        // Detect SLOAD in loops (gas varies with storage access count)
        vulnerabilities.extend(self.detect_loop_storage_access());

        vulnerabilities
    }

    fn detect_data_dependent_loops(&self) -> Vec<GasLeakage> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        let mut jump_targets = std::collections::HashSet::new();

        // First pass: identify JUMPDEST locations
        let mut scan_pc = 0;
        while scan_pc < self.bytecode.len() {
            if self.bytecode[scan_pc] == 0x5B { // JUMPDEST
                jump_targets.insert(scan_pc);
            }
            scan_pc += 1;
            if self.bytecode[scan_pc - 1] >= 0x60 && self.bytecode[scan_pc - 1] <= 0x7F {
                scan_pc += (self.bytecode[scan_pc - 1] - 0x5F) as usize;
            }
        }

        // Second pass: detect loops (JUMPI jumping backwards)
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            if opcode == 0x57 { // JUMPI (conditional jump)
                // Check if this is a backward jump (loop)
                // In practice, loops jump to earlier JUMPDEST
                let is_potential_loop = jump_targets.iter().any(|&target| target < pc && pc - target < 200);
                
                if is_potential_loop {
                    vulns.push(GasLeakage {
                        pc,
                        vulnerability_type: "DataDependentLoop".to_string(),
                        description: format!(
                            "Loop detected at PC {} (backward JUMPI). Loop iteration count affects gas consumption. \
                            If loop bound depends on secret data (array lengths, user balances, permission counts), \
                            attackers can infer the secret value by measuring transaction gas usage. Use fixed \
                            iteration counts or constant-time algorithms for sensitive operations.",
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

    fn detect_conditional_crypto(&self) -> Vec<GasLeakage> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        // Expensive operations: KECCAK256, CALL to precompiles
        let expensive_ops = [0x20, 0xF1, 0xF2, 0xF4, 0xFA]; // KECCAK256, CALL, CALLCODE, DELEGATECALL, STATICCALL

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            if expensive_ops.contains(&opcode) {
                // Check if preceded by conditional logic (JUMPI)
                let start = if pc > 30 { pc - 30 } else { 0 };
                let has_conditional = self.bytecode[start..pc].iter().any(|&b| b == 0x57); // JUMPI
                
                if has_conditional {
                    let op_name = match opcode {
                        0x20 => "KECCAK256",
                        0xF1 => "CALL",
                        0xF2 => "CALLCODE",
                        0xF4 => "DELEGATECALL",
                        0xFA => "STATICCALL",
                        _ => "UNKNOWN",
                    };
                    
                    vulns.push(GasLeakage {
                        pc,
                        vulnerability_type: "ConditionalExpensiveOp".to_string(),
                        description: format!(
                            "Conditional {} operation at PC {}. Expensive operation execution depends on \
                            branch condition. Gas consumption differs significantly between paths. If condition \
                            involves secret data, attackers can determine which branch was taken by measuring \
                            gas usage, leaking information about: access levels, validation results, or internal state.",
                            op_name, pc
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

    fn detect_loop_storage_access(&self) -> Vec<GasLeakage> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for SLOAD/SSTORE followed by backward JUMPI (loop with storage access)
            if opcode == 0x54 || opcode == 0x55 { // SLOAD or SSTORE
                let window_end = (pc + 30).min(self.bytecode.len());
                for check_pc in (pc + 1)..window_end {
                    if self.bytecode[check_pc] == 0x57 { // JUMPI
                        let op_name = if opcode == 0x54 { "SLOAD" } else { "SSTORE" };
                        vulns.push(GasLeakage {
                            pc,
                            vulnerability_type: "LoopStorageAccess".to_string(),
                            description: format!(
                                "{} at PC {} inside loop structure. Storage operations in loops create \
                                variable gas consumption based on iteration count. This reveals: (1) Array/mapping \
                                sizes, (2) Number of permissions/users, (3) Data structure complexity. \
                                Each storage operation costs 2100 gas (cold) or 100 gas (warm), making \
                                iteration counts easily measurable.",
                                op_name, pc
                            ),
                            confidence: 0.85,
                        });
                        break;
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
