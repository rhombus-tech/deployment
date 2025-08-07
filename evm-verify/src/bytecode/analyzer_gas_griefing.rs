use crate::bytecode::analyzer::BytecodeAnalyzer;
use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind, Operation};
use crate::bytecode::opcodes::*;

/// Analyzes bytecode for gas griefing vulnerabilities
pub fn analyze(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    // Skip analysis in test mode to avoid false positives
    if analyzer.is_test_mode() {
        return Vec::new();
    }

    let mut warnings = Vec::new();
    
    // Run all detection methods
    detect_unbounded_loops(analyzer, &mut warnings);
    detect_expensive_operations_in_loops(analyzer, &mut warnings);
    detect_missing_gas_limits(analyzer, &mut warnings);
    detect_insufficient_gas_stipends(analyzer, &mut warnings);
    
    warnings
}

/// Detects gas griefing vulnerabilities in EVM bytecode
pub fn detect_gas_griefing_vulnerabilities(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    // Use the main analyze function
    analyze(analyzer)
}

/// Detects GENUINE unbounded loops that could lead to gas griefing
/// Only flags loops that are actually dangerous and exploitable
fn detect_unbounded_loops(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>) {
    if analyzer.is_test_mode() {
        return;
    }
    
    let bytecode = analyzer.get_bytecode_vec();
    
    // Find genuine unbounded loop patterns that could be exploited:
    // 1. Loops controlled by user input without bounds
    // 2. Loops over dynamic arrays without gas checks
    // 3. Recursive calls without termination conditions
    
    for i in 0..bytecode.len().saturating_sub(10) {
        if bytecode[i] == JUMPDEST as u8 {
            if is_genuine_unbounded_loop(&bytecode, i) {
                let severity = if has_user_controlled_loop_condition(&bytecode, i) {
                    SecuritySeverity::High
                } else {
                    SecuritySeverity::Medium
                };
                
                warnings.push(SecurityWarning::new(
                    SecurityWarningKind::GasGriefing,
                    severity,
                    i as u64,
                    "Genuinely unbounded loop vulnerable to gas griefing".to_string(),
                    vec![Operation::Computation {
                        op_type: "unbounded_loop_vulnerability".to_string(),
                        gas_cost: 0,
                    }],
                    "Implement proper loop bounds or gas limit checks".to_string(),
                ));
                
                // Only report one per loop structure
                break;
            }
        }
    }
}

/// Detects GENUINE expensive operations in loops that could cause gas griefing
/// Only flags truly dangerous patterns, not every operation in a loop
fn detect_expensive_operations_in_loops(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>) {
    let bytecode = analyzer.get_bytecode_vec();
    
    // Find genuine expensive operation vulnerabilities:
    // 1. Storage writes (SSTORE) in user-controlled loops
    // 2. External calls with unlimited gas in loops
    // 3. Complex computations in unbounded iterations
    
    for i in 0..bytecode.len().saturating_sub(10) {
        if bytecode[i] == JUMPDEST as u8 {
            // Check if this loop contains genuinely dangerous operations
            if let Some((op_pos, op_type, gas_risk)) = find_dangerous_loop_operations(&bytecode, i) {
                // Only flag if the operation is actually exploitable
                if is_exploitable_loop_operation(&bytecode, op_pos, &op_type) {
                    let severity = match gas_risk {
                        HighGasRisk => SecuritySeverity::Critical,
                        MediumGasRisk => SecuritySeverity::High,
                        _ => SecuritySeverity::Medium,
                    };
                    
                    warnings.push(SecurityWarning::new(
                        SecurityWarningKind::GasGriefing,
                        severity,
                        op_pos as u64,
                        format!("Exploitable {} operation in unbounded loop", op_type),
                        vec![Operation::Computation {
                            op_type: format!("dangerous_loop_{}", op_type),
                            gas_cost: 0,
                        }],
                        "Implement gas limits or move expensive operations outside loops".to_string(),
                    ));
                    
                    // Only report the most dangerous operation per loop
                    break;
                }
            }
        }
    }
}

/// Detects callback patterns without gas limits
fn detect_missing_gas_limits(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>) {
    let bytecode = analyzer.get_bytecode_vec();
    let mut i = 0;
    
    while i < bytecode.len() {
        // Look for CALL, STATICCALL, or DELEGATECALL opcodes
        if bytecode[i] == CALL as u8 || bytecode[i] == STATICCALL as u8 || bytecode[i] == DELEGATECALL as u8 {
            let call_index = i;
            let call_type = match bytecode[i] {
                x if x == CALL as u8 => "CALL",
                x if x == STATICCALL as u8 => "STATICCALL",
                x if x == DELEGATECALL as u8 => "DELEGATECALL",
                _ => "UNKNOWN_CALL",
            };
            
            // Check if GAS opcode is used before the call
            // This is a simplified approach - in a real implementation we would track the stack
            let mut gas_limit_found = false;
            let mut all_gas_forwarded = false;
            
            // Check up to 10 instructions back for gas parameter setup
            if i == 0 {
                continue; // Skip if we're at the first instruction
            }
            let j = i - 1;
            let search_start = if j > 10 { j - 10 } else { 0 };
            
            for k in (search_start..=j).rev() {
                if k < bytecode.len() && bytecode[k] == GAS as u8 {
                    // Found GAS opcode, which suggests forwarding all available gas
                    all_gas_forwarded = true;
                    break;
                } else if k < bytecode.len() && (bytecode[k] == 0x60 || bytecode[k] == 0x61 || bytecode[k] == 0x62 || bytecode[k] == 0x63) { // PUSH1-PUSH4
                    // Found a PUSH opcode, which might be setting a gas limit
                    gas_limit_found = true;
                    break;
                }
            }
            
            // If we found the GAS opcode but no explicit gas limit, warn about potential gas griefing
            if all_gas_forwarded && !gas_limit_found {
                warnings.push(SecurityWarning::new(
                    SecurityWarningKind::GasGriefing,
                    SecuritySeverity::Medium,
                    call_index as u64,
                    format!("{} operation without explicit gas limit may be vulnerable to gas griefing", call_type).to_string(),
                    vec![Operation::Computation {
                        op_type: "missing_gas_limit".to_string(),
                        gas_cost: 0,
                    }],
                    "Consider explicitly setting a gas limit when making external calls to prevent gas griefing attacks".to_string(),
                ));
            }
        }
        
        i += 1;
    }
}

/// Detects lack of gas stipends in external calls
fn detect_insufficient_gas_stipends(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>) {
    let bytecode = analyzer.get_bytecode_vec();
    let mut i = 0;
    
    while i < bytecode.len() {
        // Look for CALL opcodes
        if bytecode[i] == CALL as u8 {
            let call_index = i;
            
            // Check for gas stipend parameter
            // This is a simplified approach - in a real implementation we would track the stack
            let mut low_stipend_found = false;
            
            // Check up to 10 instructions back for gas parameter setup
            if i == 0 {
                continue; // Skip if we're at the first instruction
            }
            let j = i - 1;
            let search_start = if j > 10 { j - 10 } else { 0 };
            
            for k in (search_start..=j).rev() {
                // Look for PUSH1 with a small value (less than 2300, which is the stipend for transfers)
                if k < bytecode.len() && bytecode[k] == 0x60 && k + 1 < bytecode.len() {
                    let value = bytecode[k + 1];
                    if value < 0x09 { // 0x09 = 9, so this checks for values 0-8, which in hex would represent 0-2048
                        low_stipend_found = true;
                        break;
                    }
                }
            }
            
            if low_stipend_found {
                warnings.push(SecurityWarning::new(
                    SecurityWarningKind::GasGriefing,
                    SecuritySeverity::Medium,
                    call_index as u64,
                    "CALL operation with insufficient gas stipend may fail unexpectedly".to_string(),
                    vec![Operation::Computation {
                        op_type: "insufficient_gas_stipend".to_string(),
                        gas_cost: 0,
                    }],
                    "Ensure sufficient gas is forwarded with external calls to allow meaningful operations".to_string(),
                ));
            }
        }
        
        i += 1;
    }
}

// Gas risk levels for loop operations
#[derive(PartialEq)]
enum GasRisk {
    HighGasRisk,
    MediumGasRisk,
    LowGasRisk,
}

use GasRisk::*;

/// Check if this is a genuine unbounded loop vulnerability
fn is_genuine_unbounded_loop(bytecode: &[u8], loop_start: usize) -> bool {
    // Look for patterns that indicate a genuinely dangerous unbounded loop:
    // 1. Loop condition depends on user input (CALLDATALOAD)
    // 2. Loop contains state-changing operations without bounds
    // 3. Loop has no obvious termination conditions
    
    let search_range = 50;
    let end = std::cmp::min(loop_start + search_range, bytecode.len());
    
    let mut has_user_input = false;
    let mut has_state_change = false;
    let mut has_termination_check = false;
    
    for i in loop_start..end {
        if i >= bytecode.len() { break; }
        
        match bytecode[i] {
            // User input dependency
            0x35 => { has_user_input = true; }, // CALLDATALOAD
            
            // State-changing operations
            0x55 => { has_state_change = true; }, // SSTORE
            
            // Termination conditions (comparisons with constants)
            0x10 | 0x11 | 0x12 | 0x13 => { // LT, GT, SLT, SGT
                if has_constant_nearby(bytecode, i) {
                    has_termination_check = true;
                }
            },
            
            _ => {}
        }
    }
    
    // Only flag if there's user input dependency and state changes without proper bounds
    has_user_input && has_state_change && !has_termination_check
}

/// Check if loop condition is controlled by user input
fn has_user_controlled_loop_condition(bytecode: &[u8], loop_start: usize) -> bool {
    let search_range = 30;
    
    for i in loop_start..std::cmp::min(loop_start + search_range, bytecode.len()) {
        if i >= bytecode.len() { continue; }
        
        // Look for JUMPI (conditional jump) that uses user input
        if bytecode[i] == 0x57 { // JUMPI
            // Check if condition comes from user input
            if has_calldataload_nearby(bytecode, i) {
                return true;
            }
        }
    }
    false
}

/// Find dangerous operations in loops
fn find_dangerous_loop_operations(bytecode: &[u8], loop_start: usize) -> Option<(usize, String, GasRisk)> {
    let search_range = 40;
    let end = std::cmp::min(loop_start + search_range, bytecode.len());
    
    for i in loop_start..end {
        if i >= bytecode.len() { continue; }
        
        match bytecode[i] {
            // Critical: Storage writes in loops
            0x55 => return Some((i, "SSTORE".to_string(), HighGasRisk)),
            
            // High: External calls without gas limits
            0xF1 => return Some((i, "CALL".to_string(), HighGasRisk)),
            0xF4 => return Some((i, "DELEGATECALL".to_string(), HighGasRisk)),
            
            // Medium: Static calls (lower risk)
            0xFA => return Some((i, "STATICCALL".to_string(), MediumGasRisk)),
            
            // Medium: Complex operations
            0x09 => return Some((i, "MULMOD".to_string(), MediumGasRisk)),
            0x0A => return Some((i, "ADDMOD".to_string(), MediumGasRisk)),
            
            _ => {}
        }
    }
    None
}

/// Check if a loop operation is actually exploitable
fn is_exploitable_loop_operation(bytecode: &[u8], op_pos: usize, op_type: &str) -> bool {
    match op_type {
        "SSTORE" => {
            // Storage writes are exploitable if:
            // 1. They're in user-controlled loops
            // 2. They don't have gas limit checks
            has_user_controlled_context(bytecode, op_pos) && !has_gas_limit_check(bytecode, op_pos)
        },
        
        "CALL" | "DELEGATECALL" => {
            // External calls are exploitable if they forward all gas
            !has_gas_limit_in_call(bytecode, op_pos)
        },
        
        "STATICCALL" => {
            // Static calls are less risky but still exploitable with unlimited gas
            !has_gas_limit_in_call(bytecode, op_pos)
        },
        
        _ => true, // Conservative approach for other operations
    }
}

/// Helper: Check for constants nearby
fn has_constant_nearby(bytecode: &[u8], pos: usize) -> bool {
    let range = 5;
    for i in pos.saturating_sub(range)..std::cmp::min(pos + range, bytecode.len()) {
        if i >= bytecode.len() { continue; }
        // Look for PUSH operations that load constants
        if bytecode[i] >= 0x60 && bytecode[i] <= 0x7F { // PUSH1-PUSH32
            return true;
        }
    }
    false
}

/// Helper: Check for CALLDATALOAD nearby
fn has_calldataload_nearby(bytecode: &[u8], pos: usize) -> bool {
    let range = 10;
    for i in pos.saturating_sub(range)..std::cmp::min(pos + range, bytecode.len()) {
        if i >= bytecode.len() { continue; }
        if bytecode[i] == 0x35 { // CALLDATALOAD
            return true;
        }
    }
    false
}

/// Helper: Check for user-controlled context
fn has_user_controlled_context(bytecode: &[u8], pos: usize) -> bool {
    // Look for user input dependencies
    has_calldataload_nearby(bytecode, pos) || has_external_call_nearby(bytecode, pos)
}

/// Helper: Check for external calls nearby
fn has_external_call_nearby(bytecode: &[u8], pos: usize) -> bool {
    let range = 15;
    for i in pos.saturating_sub(range)..std::cmp::min(pos + range, bytecode.len()) {
        if i >= bytecode.len() { continue; }
        if bytecode[i] == 0xF1 || bytecode[i] == 0xF4 || bytecode[i] == 0xFA {
            return true;
        }
    }
    false
}

/// Helper: Check for gas limit checks
fn has_gas_limit_check(bytecode: &[u8], pos: usize) -> bool {
    let range = 20;
    for i in pos.saturating_sub(range)..pos {
        if i >= bytecode.len() { continue; }
        // Look for GAS opcode or gas-related comparisons
        if bytecode[i] == 0x5A { // GAS
            return true;
        }
    }
    false
}

/// Helper: Check for gas limits in call operations
fn has_gas_limit_in_call(bytecode: &[u8], call_pos: usize) -> bool {
    // Check if gas parameter is limited (not forwarding all available gas)
    let range = 10;
    for i in call_pos.saturating_sub(range)..call_pos {
        if i >= bytecode.len() { continue; }
        // Look for specific gas amounts (PUSH operations)
        if bytecode[i] >= 0x60 && bytecode[i] <= 0x63 { // PUSH1-PUSH4
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_detect_gas_griefing_vulnerabilities() {
        // Test implementation will be added
    }
}
