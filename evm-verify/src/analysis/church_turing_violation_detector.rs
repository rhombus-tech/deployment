use crate::bytecode::SecurityFinding;

pub struct ChurchTuringViolationDetector {
    bytecode: Vec<u8>,
}

impl ChurchTuringViolationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SecurityFinding> {
        self.detect()
    }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_halting_problem_assumption() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Contract assumes decidability of halting problem at PC {}. \
                    Unbounded loops or recursive calls may never terminate, causing DOS.",
                    pc
                ),
                pc,
                confidence: 0.82,
            });
        }

        if let Some(pc) = self.detect_oracle_computation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Contract relies on non-computable oracle at PC {}. \
                    External computation assumed to solve undecidable problems.",
                    pc
                ),
                pc,
                confidence: 0.80,
            });
        }

        if let Some(pc) = self.detect_unbounded_iteration() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!(
                    "Unbounded computation without termination guarantee at PC {}. \
                    May exceed gas limits or create unpredictable execution.",
                    pc
                ),
                pc,
                confidence: 0.78,
            });
        }

        findings
    }

    fn detect_halting_problem_assumption(&self) -> Option<usize> {
        // Look for unbounded loops without clear termination conditions
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // executeWhile, processAll, iterateUntil selectors
                if matches!(selector, [0xa1, 0x3e, _, _] | [0xb2, 0x4f, _, _] | [0xc3, 0x5d, _, _]) {
                    let mut has_loop = false;
                    let mut has_bounded_iterations = false;
                    let mut has_gas_check = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Detect loop structure (JUMPI back to earlier PC)
                        if j + 4 < self.bytecode.len() {
                            if self.bytecode[j] == 0x57 { // JUMPI
                                has_loop = true;
                            }
                        }
                        
                        // Check for iteration counter with maximum
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (counter)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x10 && // LT (max iterations)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x15 { // ISZERO (break if >= max)
                                has_bounded_iterations = true;
                            }
                        }
                        
                        // Check for gas limit checks
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x5a && // GAS
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x10 { // LT (gas threshold)
                                has_gas_check = true;
                            }
                        }
                    }
                    
                    if has_loop && !has_bounded_iterations && !has_gas_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_oracle_computation(&self) -> Option<usize> {
        // Look for external calls expecting solutions to hard problems
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // solveNP, computeOptimal, findSolution selectors
                if matches!(selector, [0xd1, 0x3e, _, _] | [0xe2, 0x4f, _, _] | [0xf3, 0x5c, _, _]) {
                    let mut makes_external_call = false;
                    let mut validates_complexity = false;
                    let mut has_timeout = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for external oracle call
                        if self.bytecode[j] == 0xf1 || // CALL
                           self.bytecode[j] == 0xfa { // STATICCALL
                            makes_external_call = true;
                        }
                        
                        // Check for computational complexity validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (input size)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x10 { // LT (feasible size)
                                validates_complexity = true;
                            }
                        }
                        
                        // Check for timeout mechanism
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x03 && // SUB
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x10 { // LT (timeout check)
                                has_timeout = true;
                            }
                        }
                    }
                    
                    if makes_external_call && !validates_complexity && !has_timeout {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_unbounded_iteration(&self) -> Option<usize> {
        // Look for array/list processing without size limits
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // processAll, batchExecute, forEach selectors
                if matches!(selector, [0xa2, 0x3e, _, _] | [0xb3, 0x4f, _, _] | [0xc4, 0x5d, _, _]) {
                    let mut iterates_array = false;
                    let mut has_size_limit = false;
                    let mut uses_pagination = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for array iteration
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (array length)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x57 { // JUMPI (loop)
                                iterates_array = true;
                            }
                        }
                        
                        // Check for maximum size validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (length)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x10 && // LT (max size)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x15 { // ISZERO (require)
                                has_size_limit = true;
                            }
                        }
                        
                        // Check for pagination (offset/limit pattern)
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (offset)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x35 && // CALLDATALOAD (limit)
                               j + 8 < self.bytecode.len() &&
                               self.bytecode[j + 7] == 0x01 { // ADD (offset + limit)
                                uses_pagination = true;
                            }
                        }
                    }
                    
                    if iterates_array && !has_size_limit && !uses_pagination {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
