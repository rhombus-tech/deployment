use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelockRaceVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TimelockMultisigRaceConditionDetector {
    bytecode: Vec<u8>,
}

impl TimelockMultisigRaceConditionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<TimelockRaceVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect TIMESTAMP check followed by external call without lock
        vulnerabilities.extend(self.detect_timelock_execution_gap());
        
        // Detect multiple SLOAD operations between checks (non-atomic)
        vulnerabilities.extend(self.detect_non_atomic_validation());
        
        // Detect CALL after timelock without reentrancy guard
        vulnerabilities.extend(self.detect_unguarded_execution());

        vulnerabilities
    }

    fn detect_timelock_execution_gap(&self) -> Vec<TimelockRaceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for TIMESTAMP operation
            if opcode == 0x42 { // TIMESTAMP
                let window_end = (pc + 100).min(self.bytecode.len());
                let mut has_comparison = false;
                let mut has_call = false;
                let mut has_sstore_lock = false;
                
                // Check for time comparison (GT/LT)
                for check_pc in (pc + 1)..window_end {
                    if self.bytecode[check_pc] == 0x10 || self.bytecode[check_pc] == 0x11 {
                        has_comparison = true;
                    }
                    // Check for CALL after timestamp check
                    if self.bytecode[check_pc] == 0xF1 || self.bytecode[check_pc] == 0xF4 {
                        has_call = true;
                    }
                    // Check for SSTORE before call (lock pattern)
                    if self.bytecode[check_pc] == 0x55 && !has_call {
                        has_sstore_lock = true;
                    }
                }
                
                if has_comparison && has_call && !has_sstore_lock {
                    vulns.push(TimelockRaceVulnerability {
                        pc,
                        vulnerability_type: "TimelockExecutionGap".to_string(),
                        description: format!(
                            "Timelock check at PC {} followed by execution without lock. Race condition: \
                            Between timestamp check passing and execution, multiple transactions can execute \
                            simultaneously once timelock expires. This enables: (1) Double-execution attacks, \
                            (2) Front-running the timelock expiry, (3) Unauthorized parallel executions. \
                            Use reentrancy guard or mark as executed before external call.",
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

    fn detect_non_atomic_validation(&self) -> Vec<TimelockRaceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for SLOAD operations
            if opcode == 0x54 { // SLOAD
                let window_end = (pc + 50).min(self.bytecode.len());
                let mut sload_count = 1;
                let mut has_comparison = false;
                
                // Count multiple SLOADs (checking different state variables)
                for check_pc in (pc + 1)..window_end {
                    if self.bytecode[check_pc] == 0x54 {
                        sload_count += 1;
                    }
                    if self.bytecode[check_pc] >= 0x10 && self.bytecode[check_pc] <= 0x14 {
                        has_comparison = true;
                    }
                }
                
                // Multiple SLOADs with comparisons suggests multi-step validation
                if sload_count >= 3 && has_comparison {
                    vulns.push(TimelockRaceVulnerability {
                        pc,
                        vulnerability_type: "NonAtomicValidation".to_string(),
                        description: format!(
                            "Multiple storage reads starting at PC {} for validation. Non-atomic checks: \
                            timelock expiry, signature count, execution status checked separately. \
                            State can change between checks via reentrancy. Attacker can: \
                            (1) Pass timelock check, (2) Reenter and modify signatures, (3) Execute with invalid state. \
                            Load all validation data atomically or use reentrancy lock.",
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

    fn detect_unguarded_execution(&self) -> Vec<TimelockRaceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for CALL/DELEGATECALL
            if opcode == 0xF1 || opcode == 0xF4 {
                let start = if pc > 150 { pc - 150 } else { 0 };
                
                // Check if TIMESTAMP check exists before call
                let has_timelock = self.bytecode[start..pc].iter().any(|&b| b == 0x42);
                
                // Check if reentrancy guard exists (SSTORE pattern)
                let mut has_guard = false;
                let mut temp_pc = start;
                while temp_pc < pc {
                    // Look for SSTORE followed by check pattern (status flag)
                    if self.bytecode[temp_pc] == 0x55 {
                        // Check if this SSTORE is followed by a check later
                        let guard_check_end = (temp_pc + 80).min(pc);
                        if self.bytecode[(temp_pc + 1)..guard_check_end].iter().any(|&b| b == 0x14) {
                            has_guard = true;
                            break;
                        }
                    }
                    temp_pc += 1;
                }
                
                if has_timelock && !has_guard {
                    vulns.push(TimelockRaceVulnerability {
                        pc,
                        vulnerability_type: "UnguardedTimelockExecution".to_string(),
                        description: format!(
                            "External call at PC {} after timelock without reentrancy protection. \
                            Vulnerable to: (1) Reentrancy during execution, (2) Multiple parallel executions \
                            after timelock expires, (3) State manipulation between timelock check and execution. \
                            Add nonReentrant modifier or set executed=true before external call.",
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
