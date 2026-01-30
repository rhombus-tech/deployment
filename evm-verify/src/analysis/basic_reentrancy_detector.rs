// Basic intra-contract reentrancy detector
// Detects The DAO-style vulnerabilities: external calls before state updates

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReentrancyVulnerability {
    pub pc: usize,
    pub severity: SecuritySeverity,
    pub call_opcode: u8,  // CALL, CALLCODE, DELEGATECALL
    pub state_changes_after: Vec<usize>,  // SSTORE locations after the call
    pub description: String,
    pub affected_storage_slots: Vec<u8>,
    pub has_reentrancy_guard: bool,
    pub has_access_control: bool,
    pub access_control_type: Option<String>,
    pub confidence: f32,
}

pub struct BasicReentrancyDetector {
    bytecode: Vec<u8>,
}

impl BasicReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ReentrancyVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Parse bytecode to find dangerous patterns
        let external_calls = self.find_external_calls();
        
        for call_info in external_calls {
            // Check if there are state changes (SSTORE) after this call
            let state_changes = self.find_state_changes_after(call_info.pc);
            
            if !state_changes.is_empty() {
                // Check if there's a reentrancy guard
                let has_guard = self.has_reentrancy_guard_pattern();
                
                // NEW: Check if there's access control before this call
                let (has_access_control, access_control_type) = self.has_access_control_before(call_info.pc);
                
                let severity = if call_info.is_delegatecall {
                    SecuritySeverity::Critical
                } else if state_changes.len() > 2 {
                    SecuritySeverity::High
                } else {
                    SecuritySeverity::Medium
                };
                
                // Adjust confidence based on protections
                let confidence = if has_access_control {
                    0.20  // Low confidence - has access control, likely not exploitable
                } else if !has_guard && call_info.transfers_value {
                    0.95  // Very confident - external call with value, no guard, state changes after
                } else if !has_guard {
                    0.85  // Confident - external call, no guard, state changes after
                } else {
                    0.60  // Medium confidence - has guard but still risky pattern
                };
                
                vulnerabilities.push(ReentrancyVulnerability {
                    pc: call_info.pc,
                    severity,
                    call_opcode: call_info.opcode,
                    state_changes_after: state_changes.clone(),
                    description: format!(
                        "Potential reentrancy: {} at PC {} followed by {} state changes. \
                        External call occurs BEFORE state updates, allowing reentrancy attacks. \
                        {} {}",
                        Self::opcode_name(call_info.opcode),
                        call_info.pc,
                        state_changes.len(),
                        if has_access_control { 
                            format!("Access control detected ({}). Likely requires authorization.", 
                                    access_control_type.as_ref().unwrap_or(&"unknown".to_string())) 
                        } else { "No access control detected - publicly callable!".to_string() },
                        if has_guard { "Reentrancy guard detected but verify its correctness." } 
                        else { "No reentrancy guard detected!" }
                    ),
                    affected_storage_slots: vec![],
                    has_reentrancy_guard: has_guard,
                    has_access_control,
                    access_control_type,
                    confidence,
                });
            }
        }
        
        vulnerabilities
    }
    
    fn find_external_calls(&self) -> Vec<CallInfo> {
        let mut calls = Vec::new();
        let mut pc = 0;
        
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            match opcode {
                0xF1 => {  // CALL
                    calls.push(CallInfo {
                        pc,
                        opcode: 0xF1,
                        is_delegatecall: false,
                        transfers_value: true,  // CALL can transfer value
                    });
                }
                0xF2 => {  // CALLCODE
                    calls.push(CallInfo {
                        pc,
                        opcode: 0xF2,
                        is_delegatecall: false,
                        transfers_value: true,
                    });
                }
                0xF4 => {  // DELEGATECALL (most dangerous)
                    calls.push(CallInfo {
                        pc,
                        opcode: 0xF4,
                        is_delegatecall: true,
                        transfers_value: false,
                    });
                }
                0xFA => {  // STATICCALL (read-only, safe)
                    // Don't add - can't modify state
                }
                _ => {}
            }
            
            pc += 1;
            
            // Skip PUSH data
            if opcode >= 0x60 && opcode <= 0x7F {
                let push_bytes = (opcode - 0x5F) as usize;
                pc += push_bytes;
            }
        }
        
        calls
    }
    
    fn find_state_changes_after(&self, call_pc: usize) -> Vec<usize> {
        let mut changes = Vec::new();
        let mut pc = call_pc + 1;
        let mut instructions_checked = 0;
        const MAX_INSTRUCTIONS: usize = 100;  // Check next 100 instructions
        
        while pc < self.bytecode.len() && instructions_checked < MAX_INSTRUCTIONS {
            let opcode = self.bytecode[pc];
            
            // Found state change
            if opcode == 0x55 {  // SSTORE
                changes.push(pc);
            }
            
            // Stop at next external call or return
            if matches!(opcode, 0xF1 | 0xF2 | 0xF4 | 0xF3 | 0xFD) {
                break;
            }
            
            pc += 1;
            instructions_checked += 1;
            
            // Skip PUSH data
            if opcode >= 0x60 && opcode <= 0x7F {
                let push_bytes = (opcode - 0x5F) as usize;
                pc += push_bytes;
            }
        }
        
        changes
    }
    
    fn has_reentrancy_guard_pattern(&self) -> bool {
        // Look for common reentrancy guard patterns:
        // 1. Check storage slot (SLOAD)
        // 2. Compare to 0 or 1 (EQ/ISZERO)
        // 3. Revert if already entered (JUMPI to revert)
        // 4. Set guard (SSTORE 1)
        // 5. Execute function
        // 6. Unset guard (SSTORE 0)
        
        let mut pc = 0;
        let mut has_guard_check = false;
        let mut has_guard_set = false;
        let mut guard_storage_slot = None;
        
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Pattern: SLOAD followed by comparison
            if opcode == 0x54 {  // SLOAD
                // Next few opcodes should be comparison
                if pc + 10 < self.bytecode.len() {
                    let next_opcodes = &self.bytecode[pc+1..pc+10];
                    // Look for ISZERO (0x15) or EQ (0x14)
                    if next_opcodes.contains(&0x15) || next_opcodes.contains(&0x14) {
                        has_guard_check = true;
                        guard_storage_slot = Some(pc);
                    }
                }
            }
            
            // Pattern: SSTORE with value 1 or 0 (setting guard)
            if opcode == 0x55 && has_guard_check {  // SSTORE
                has_guard_set = true;
            }
            
            pc += 1;
            
            // Skip PUSH data
            if opcode >= 0x60 && opcode <= 0x7F {
                let push_bytes = (opcode - 0x5F) as usize;
                pc += push_bytes;
            }
        }
        
        has_guard_check && has_guard_set
    }
    
    fn has_access_control_before(&self, call_pc: usize) -> (bool, Option<String>) {
        // Look for access control patterns BEFORE the vulnerable call
        // Common patterns:
        // 1. CALLER + SLOAD + EQ + JUMPI (msg.sender == owner check)
        // 2. CALLER + EQ + JUMPI (direct address check)
        // 3. ORIGIN + check (tx.origin check)
        
        let start_pc = if call_pc > 200 { call_pc - 200 } else { 0 };
        let mut pc = start_pc;
        
        let mut has_caller_check = false;
        let mut has_origin_check = false;
        let mut has_sload_comparison = false;
        
        while pc < call_pc {
            if pc >= self.bytecode.len() {
                break;
            }
            let opcode = self.bytecode[pc];
            
            // Check for CALLER opcode (0x33)
            if opcode == 0x33 {
                // Look ahead for comparison pattern
                if pc + 20 < self.bytecode.len() {
                    let next_opcodes = &self.bytecode[pc+1..std::cmp::min(pc+20, self.bytecode.len())];
                    // Look for EQ (0x14) followed by JUMPI (0x57) or ISZERO (0x15)
                    for i in 0..next_opcodes.len().saturating_sub(2) {
                        if (next_opcodes[i] == 0x14 || next_opcodes[i] == 0x15) && 
                           next_opcodes[i+1] == 0x57 {
                            has_caller_check = true;
                            break;
                        }
                    }
                }
            }
            
            // Check for ORIGIN opcode (0x32)
            if opcode == 0x32 {
                if pc + 20 < self.bytecode.len() {
                    let next_opcodes = &self.bytecode[pc+1..std::cmp::min(pc+20, self.bytecode.len())];
                    for i in 0..next_opcodes.len().saturating_sub(2) {
                        if (next_opcodes[i] == 0x14 || next_opcodes[i] == 0x15) && 
                           next_opcodes[i+1] == 0x57 {
                            has_origin_check = true;
                            break;
                        }
                    }
                }
            }
            
            // Check for SLOAD + comparison pattern (storage-based access control)
            if opcode == 0x54 {  // SLOAD
                if pc + 15 < self.bytecode.len() {
                    let next_opcodes = &self.bytecode[pc+1..std::cmp::min(pc+15, self.bytecode.len())];
                    // Look for comparison with CALLER
                    if next_opcodes.contains(&0x33) {  // CALLER present
                        for i in 0..next_opcodes.len().saturating_sub(2) {
                            if next_opcodes[i] == 0x14 && next_opcodes[i+1] == 0x57 {
                                has_sload_comparison = true;
                                break;
                            }
                        }
                    }
                }
            }
            
            pc += 1;
            
            // Skip PUSH data
            if opcode >= 0x60 && opcode <= 0x7F {
                let push_bytes = (opcode - 0x5F) as usize;
                pc += push_bytes;
            }
        }
        
        if has_caller_check || has_sload_comparison {
            (true, Some("msg.sender check".to_string()))
        } else if has_origin_check {
            (true, Some("tx.origin check".to_string()))
        } else {
            (false, None)
        }
    }
    
    fn opcode_name(opcode: u8) -> &'static str {
        match opcode {
            0xF1 => "CALL",
            0xF2 => "CALLCODE",
            0xF4 => "DELEGATECALL",
            0xFA => "STATICCALL",
            _ => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone)]
struct CallInfo {
    pc: usize,
    opcode: u8,
    is_delegatecall: bool,
    transfers_value: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_dao_pattern() {
        // Simplified DAO-like bytecode pattern:
        // CALL followed by SSTORE
        let bytecode = vec![
            0x60, 0x00,  // PUSH1 0x00
            0xF1,        // CALL (external call)
            0x60, 0x00,  // PUSH1 0x00
            0x55,        // SSTORE (state change AFTER call - vulnerable!)
        ];
        
        let detector = BasicReentrancyDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty(), "Should detect reentrancy vulnerability");
        assert_eq!(vulns[0].call_opcode, 0xF1);
    }
    
    #[test]
    fn test_safe_pattern() {
        // Safe pattern: SSTORE before CALL
        let bytecode = vec![
            0x60, 0x00,  // PUSH1 0x00
            0x55,        // SSTORE (state change BEFORE call - safe!)
            0x60, 0x00,  // PUSH1 0x00
            0xF1,        // CALL
        ];
        
        let detector = BasicReentrancyDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        // Should not detect vulnerability (state change is before call)
        assert!(vulns.is_empty(), "Should not flag safe pattern");
    }
}
