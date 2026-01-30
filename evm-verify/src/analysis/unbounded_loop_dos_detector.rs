/// Unbounded Loop DoS Detector
/// 
/// Detects loops that can consume unbounded gas, causing DoS.
/// Common in: withdraw all, distribute to array, delete large arrays
/// 
/// Famous exploits: GovernMental, King of Ether

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnboundedLoopDoS {
    pub vulnerability_type: String,
    pub severity: String,
    pub location: usize,
    pub description: String,
    pub loop_type: LoopType,
    pub gas_consumption: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoopType {
    ArrayIteration,      // for(uint i=0; i<array.length; i++)
    MappingIteration,    // while(hasNext) { process(mapping[key]); key = next[key]; }
    UnboundedWhile,      // while(condition) without guaranteed termination
    DeleteArray,         // delete largeArray
}

pub struct UnboundedLoopDoSDetector {
    bytecode: Vec<u8>,
}

impl UnboundedLoopDoSDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect(&self) -> Vec<UnboundedLoopDoS> {
        let mut vulnerabilities = Vec::new();
        
        // Detect different types of unbounded loops
        vulnerabilities.extend(self.detect_array_length_loops());
        vulnerabilities.extend(self.detect_storage_iteration_loops());
        vulnerabilities.extend(self.detect_unbounded_while_loops());
        vulnerabilities.extend(self.detect_array_deletion());
        vulnerabilities.extend(self.detect_external_call_in_loop());
        
        vulnerabilities
    }
    
    fn detect_array_length_loops(&self) -> Vec<UnboundedLoopDoS> {
        let mut vulns = Vec::new();
        
        // Pattern: Loop that iterates based on array length
        // SLOAD (length) -> Loop -> SLOAD/SSTORE (array access)
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // Look for backward jump (loop)
            if self.bytecode[i] == 0x57 { // JUMPI (conditional jump in loop)
                let loop_start = i;
                
                // Check if loop condition uses array length
                let uses_array_length = self.bytecode[loop_start.saturating_sub(30)..loop_start]
                    .iter()
                    .any(|&op| op == 0x54); // SLOAD for length
                
                if uses_array_length {
                    // Check if loop body has SSTORE or external calls
                    let end = (loop_start + 100).min(self.bytecode.len());
                    let has_expensive_ops = if end > loop_start {
                        self.bytecode[loop_start..end]
                            .iter()
                            .any(|&op| op == 0x55 || op == 0xF1 || op == 0xF4) // SSTORE, CALL, DELEGATECALL
                    } else {
                        false
                    };
                    
                    if has_expensive_ops {
                        vulns.push(UnboundedLoopDoS {
                            vulnerability_type: "Unbounded Array Iteration Loop".to_string(),
                            severity: "High".to_string(),
                            location: loop_start,
                            description: "Loop iterates over array length with expensive operations per iteration".to_string(),
                            loop_type: LoopType::ArrayIteration,
                            gas_consumption: "O(n) where n is unbounded array length".to_string(),
                            exploit_scenario: "Attacker fills array with many elements, causing function to exceed block gas limit and always revert".to_string(),
                            remediation: "Use pagination pattern or process in batches with gas limits".to_string(),
                        });
                    }
                }
            }
        }
        
        vulns
    }
    
    fn detect_storage_iteration_loops(&self) -> Vec<UnboundedLoopDoS> {
        let mut vulns = Vec::new();
        
        // Pattern: Loop that iterates through linked list in storage
        // while(current != 0) { process(current); current = next[current]; }
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0x5B { // JUMPDEST (loop target)
                let loop_target = i;
                
                // Look for backward jump to this target
                let end = (i + 150).min(self.bytecode.len());
                for j in i+10..end {
                    if self.bytecode[j] == 0x57 || self.bytecode[j] == 0x56 { // JUMPI or JUMP
                        // Check if this creates a loop
                        if self.has_backward_jump_to(j, loop_target) {
                            // Check for multiple SLOADs (reading from storage in loop)
                            let sload_count = self.bytecode[loop_target..j]
                                .iter()
                                .filter(|&&op| op == 0x54)
                                .count();
                            
                            if sload_count >= 2 {
                                vulns.push(UnboundedLoopDoS {
                                    vulnerability_type: "Unbounded Storage Iteration".to_string(),
                                    severity: "Critical".to_string(),
                                    location: loop_target,
                                    description: "Loop reads from storage multiple times per iteration without bound".to_string(),
                                    loop_type: LoopType::MappingIteration,
                                    gas_consumption: format!("{} SLOAD operations per iteration, unbounded", sload_count),
                                    exploit_scenario: "Attacker creates long chain in storage, causing iteration to consume all gas".to_string(),
                                    remediation: "Add iteration limit or use pull pattern instead of push".to_string(),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        vulns
    }
    
    fn detect_unbounded_while_loops(&self) -> Vec<UnboundedLoopDoS> {
        let mut vulns = Vec::new();
        
        // Pattern: while(true) or while without clear termination
        // JUMPDEST -> operations -> JUMP (back to JUMPDEST) without clear exit
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x5B { // JUMPDEST
                // Look for unconditional backward jump (infinite loop pattern)
                let end = (i + 80).min(self.bytecode.len());
                for j in i+5..end {
                    if self.bytecode[j] == 0x56 { // JUMP (unconditional)
                        // Check if this jumps back to start
                        if self.could_jump_to(j, i) {
                            // Check if there's a JUMPI before this (exit condition)
                            let has_exit = self.bytecode[i..j]
                                .iter()
                                .any(|&op| op == 0x57); // JUMPI
                            
                            if !has_exit {
                                vulns.push(UnboundedLoopDoS {
                                    vulnerability_type: "Potentially Infinite Loop".to_string(),
                                    severity: "Medium".to_string(),
                                    location: i,
                                    description: "Loop without clear exit condition detected".to_string(),
                                    loop_type: LoopType::UnboundedWhile,
                                    gas_consumption: "Potentially infinite".to_string(),
                                    exploit_scenario: "Loop may consume all gas if exit condition fails".to_string(),
                                    remediation: "Add explicit iteration counter with maximum bound".to_string(),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        vulns
    }
    
    fn detect_array_deletion(&self) -> Vec<UnboundedLoopDoS> {
        let mut vulns = Vec::new();
        
        // Pattern: delete array - this creates a loop in Solidity
        // Compiled as loop setting each element to zero
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for pattern: loop with SSTORE to zero
            if self.bytecode[i] == 0x60 && self.bytecode[i+1] == 0x00 { // PUSH1 0
                if i+5 < self.bytecode.len() && self.bytecode[i+2] == 0x55 { // SSTORE
                    // Check if this is in a loop
                    if self.is_in_loop_context(i) {
                        vulns.push(UnboundedLoopDoS {
                            vulnerability_type: "Unbounded Array Deletion".to_string(),
                            severity: "High".to_string(),
                            location: i,
                            description: "Array deletion loops through all elements, unbounded gas consumption".to_string(),
                            loop_type: LoopType::DeleteArray,
                            gas_consumption: "20,000 gas per array element".to_string(),
                            exploit_scenario: "Large array deletion can exceed block gas limit, making function unusable".to_string(),
                            remediation: "Don't delete arrays. Instead, reset length to 0 or use mapping".to_string(),
                        });
                    }
                }
            }
        }
        
        vulns
    }
    
    fn detect_external_call_in_loop(&self) -> Vec<UnboundedLoopDoS> {
        let mut vulns = Vec::new();
        
        // Pattern: External call inside loop
        // One recipient can fail and block entire withdrawal
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0xF1 || self.bytecode[i] == 0xF4 { // CALL or DELEGATECALL
                if self.is_in_loop_context(i) {
                    vulns.push(UnboundedLoopDoS {
                        vulnerability_type: "External Call in Loop".to_string(),
                        severity: "Critical".to_string(),
                        location: i,
                        description: "External call inside loop can cause DoS if any call fails or consumes excess gas".to_string(),
                        loop_type: LoopType::ArrayIteration,
                        gas_consumption: "Unbounded - depends on called contracts".to_string(),
                        exploit_scenario: "One malicious contract in array can revert or consume all gas, blocking entire operation".to_string(),
                        remediation: "Use pull pattern - let users withdraw individually instead of pushing to all".to_string(),
                    });
                }
            }
        }
        
        vulns
    }
    
    fn has_backward_jump_to(&self, jump_pc: usize, target_pc: usize) -> bool {
        // Simplified: Check if jump could target earlier JUMPDEST
        jump_pc > target_pc
    }
    
    fn could_jump_to(&self, jump_pc: usize, target_pc: usize) -> bool {
        // Check if jump target could be the JUMPDEST at target_pc
        // In real implementation, would need to analyze stack for jump destination
        jump_pc > target_pc && (jump_pc - target_pc) < 100
    }
    
    fn is_in_loop_context(&self, pc: usize) -> bool {
        // Check if this PC is within a loop structure
        // Look for JUMPDEST before and JUMP/JUMPI after that targets earlier code
        
        let has_jumpdest_before = self.bytecode[pc.saturating_sub(50)..pc]
            .iter()
            .any(|&op| op == 0x5B);
        
        let end = (pc + 50).min(self.bytecode.len());
        let has_backward_jump_after = if end > pc {
            self.bytecode[pc..end]
                .iter()
                .any(|&op| op == 0x56 || op == 0x57) // JUMP or JUMPI
        } else {
            false
        };
        
        has_jumpdest_before && has_backward_jump_after
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_array_iteration_detection() {
        // Pattern: Loop with array access
        let bytecode = vec![
            0x54,              // SLOAD (load array length)
            0x5B,              // JUMPDEST (loop start)
            0x54,              // SLOAD (array element)
            0x55,              // SSTORE (modify)
            0x57,              // JUMPI (loop back)
        ];
        
        let detector = UnboundedLoopDoSDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.len() > 0);
    }
    
    #[test]
    fn test_external_call_in_loop() {
        let bytecode = vec![
            0x5B,              // JUMPDEST
            0xF1,              // CALL (external call in loop)
            0x57,              // JUMPI (loop)
        ];
        
        let detector = UnboundedLoopDoSDetector::new(bytecode);
        let vulns = detector.detect_external_call_in_loop();
        
        assert!(vulns.len() > 0);
    }
}
