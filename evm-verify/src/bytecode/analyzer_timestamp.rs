// Timestamp Dependency Analyzer
//
// This module provides functionality to detect timestamp dependencies in EVM bytecode.
// Timestamp dependencies can be exploited by miners to manipulate contract execution.

use crate::bytecode::types::{AnalysisResults, TimestampDependency};
use crate::bytecode::opcodes::{TIMESTAMP, LT, GT, SLT, SGT, EQ, ADD, MUL, SUB, DIV, MOD, JUMPI, JUMP};
use anyhow::Result;
use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity, Operation};
use crate::bytecode::analyzer::BytecodeAnalyzer;

/// Detect timestamp dependency vulnerabilities in bytecode
pub fn detect_timestamp_dependencies(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    // Skip analysis if in test mode
    if analyzer.is_test_mode() {
        return vec![];
    }
    
    let bytecode = analyzer.get_bytecode_vec();
    let mut warnings = Vec::new();
    
    // Scan bytecode for TIMESTAMP opcode (0x42)
    for i in 0..bytecode.len() {
        if bytecode[i] == TIMESTAMP {
            // Window size for looking ahead in the bytecode
            let window_size = 15;
            let end_idx = std::cmp::min(i + window_size, bytecode.len());
            let window = &bytecode[i+1..end_idx];
            
            // 1. Check for comparison operations (LT, GT, SLT, SGT, EQ)
            if let Some((op_idx, op_type)) = find_comparison_operation(window) {
                let pc = i as u64;
                let _abs_op_idx = i + 1 + op_idx;
                
                // Only flag DANGEROUS timestamp patterns
                if op_type == "EQ" && is_dangerous_timestamp_equality(&bytecode, i) {
                    warnings.push(SecurityWarning::new(
                        SecurityWarningKind::UnsafeTimestampComparison,
                        SecuritySeverity::High,
                        pc,
                        "Dangerous timestamp equality comparison detected. Exact timestamp matching can be manipulated by miners.".to_string(),
                        vec![Operation::Timestamp, Operation::Comparison { op_type: op_type.to_string() }],
                        "Use timestamp ranges (greater than, less than) instead of exact equality checks.".to_string()
                    ));
                } else if is_vulnerable_timestamp_dependency(&bytecode, i, &op_type) {
                    // Only flag truly vulnerable timestamp dependencies
                    warnings.push(SecurityWarning::new(
                        SecurityWarningKind::TimestampDependence,
                        SecuritySeverity::Medium,
                        pc,
                        format!("Timestamp dependency detected at offset {}. This can be manipulated by miners and should not be used for critical operations.", pc),
                        vec![Operation::Timestamp, Operation::Comparison { op_type: op_type.to_string() }],
                        "Consider using block numbers instead of timestamps for time-dependent logic, or ensure the timestamp is only used for non-critical operations.".to_string()
                    ));
                }
            }
            
            // 2. Check for control flow operations (JUMP, JUMPI)
            if let Some(op_idx) = find_control_flow_operation(window) {
                let pc = i as u64;
                let _abs_op_idx = i + 1 + op_idx;
                
                warnings.push(SecurityWarning::new(
                    SecurityWarningKind::BlockTimestampDependency,
                    SecuritySeverity::Medium,
                    pc,
                    format!("Block timestamp used in control flow decision at offset {}. This can be manipulated by miners.", pc),
                    vec![Operation::Timestamp],
                    "Avoid using block.timestamp for critical control flow decisions. Consider using block numbers or oracles for time-sensitive operations.".to_string()
                ));
            }
            
            // 3. Check for arithmetic operations (potential randomness generation)
            if let Some((op_idx, op_type)) = find_arithmetic_operation(window) {
                let pc = i as u64;
                let _abs_op_idx = i + 1 + op_idx;
                
                warnings.push(SecurityWarning::new(
                    SecurityWarningKind::TimeBasedRandomness,
                    SecuritySeverity::High,
                    pc,
                    format!("Timestamp used in arithmetic operation ({}). This may indicate an attempt to generate randomness using block.timestamp, which is predictable.", op_type),
                    vec![Operation::Timestamp, Operation::Randomness { source: "block.timestamp".to_string(), predictability: 90 }],
                    "Do not use block.timestamp for randomness. Consider using a secure randomness source like Chainlink VRF or commit-reveal schemes.".to_string()
                ));
            }
        }
    }
    
    warnings
}

/// Find comparison operations in the bytecode window
fn find_comparison_operation(bytecode: &[u8]) -> Option<(usize, &'static str)> {
    for i in 0..bytecode.len() {
        match bytecode[i] {
            LT => return Some((i, "LT")),   // Less than
            GT => return Some((i, "GT")),   // Greater than
            SLT => return Some((i, "SLT")), // Signed less than
            SGT => return Some((i, "SGT")), // Signed greater than
            EQ => return Some((i, "EQ")),   // Equal
            _ => continue,
        }
    }
    None
}

/// Find control flow operations in the bytecode window
fn find_control_flow_operation(bytecode: &[u8]) -> Option<usize> {
    for i in 0..bytecode.len() {
        match bytecode[i] {
            JUMPI => return Some(i), // Conditional jump
            JUMP => return Some(i),  // Unconditional jump (less common but possible)
            _ => continue,
        }
    }
    None
}

/// Find arithmetic operations in the bytecode window
fn find_arithmetic_operation(bytecode: &[u8]) -> Option<(usize, &'static str)> {
    for i in 0..bytecode.len() {
        match bytecode[i] {
            ADD => return Some((i, "ADD")), // Addition
            MUL => return Some((i, "MUL")), // Multiplication
            SUB => return Some((i, "SUB")), // Subtraction
            DIV => return Some((i, "DIV")), // Division
            MOD => return Some((i, "MOD")), // Modulo
            _ => continue,
        }
    }
    None
}

/// Timestamp dependency detector
pub struct TimestampDependencyDetector;

impl TimestampDependencyDetector {
    /// Detect timestamp dependencies in bytecode
    pub fn detect(bytecode: &[u8], results: &mut AnalysisResults) -> Result<()> {
        // Initialize timestamp dependencies vector if empty
        if results.timestamp_dependencies.is_empty() {
            results.timestamp_dependencies = Vec::new();
        }
        
        // Scan bytecode for TIMESTAMP opcode (0x42)
        for i in 0..bytecode.len() {
            if bytecode[i] == TIMESTAMP {
                // Look ahead for comparison operations
                if let Some(comparison_op) = Self::find_comparison_after_timestamp(&bytecode[i+1..]) {
                    // Found a timestamp comparison
                    results.timestamp_dependencies.push(TimestampDependency {
                        offset: i,
                        dependency_type: "comparison".to_string(),
                        operation: comparison_op.to_string(),
                        is_critical: Self::is_critical_path(&bytecode[i+1..]),
                        severity: Self::determine_severity(comparison_op),
                    });
                    
                    // Add a warning about timestamp dependency
                    results.warnings.push(format!(
                        "Timestamp dependency detected at offset {}. This can be manipulated by miners and should not be used for critical operations.",
                        i
                    ));
                }
                
                // Look for arithmetic operations
                if let Some(arithmetic_op) = Self::find_arithmetic_after_timestamp(&bytecode[i+1..]) {
                    // Found a timestamp arithmetic operation
                    results.timestamp_dependencies.push(TimestampDependency {
                        offset: i,
                        dependency_type: "arithmetic".to_string(),
                        operation: arithmetic_op.to_string(),
                        is_critical: false, // Arithmetic is less likely to be critical
                        severity: "medium".to_string(),
                    });
                }
            }
        }
        
        Ok(())
    }
    
    /// Find comparison operations after TIMESTAMP opcode
    fn find_comparison_after_timestamp(bytecode: &[u8]) -> Option<&'static str> {
        // Look for comparison operations within the next 10 opcodes
        for i in 0..std::cmp::min(10, bytecode.len()) {
            match bytecode[i] {
                0x10 => return Some("LT"),  // Less than
                0x11 => return Some("GT"),  // Greater than
                0x12 => return Some("SLT"), // Signed less than
                0x13 => return Some("SGT"), // Signed greater than
                0x14 => return Some("EQ"),  // Equal
                _ => continue,
            }
        }
        
        None
    }
    
    /// Find arithmetic operations after TIMESTAMP opcode
    fn find_arithmetic_after_timestamp(bytecode: &[u8]) -> Option<&'static str> {
        // Look for arithmetic operations within the next 5 opcodes
        for i in 0..std::cmp::min(5, bytecode.len()) {
            match bytecode[i] {
                0x01 => return Some("ADD"),
                0x02 => return Some("MUL"),
                0x03 => return Some("SUB"),
                0x04 => return Some("DIV"),
                0x05 => return Some("SDIV"),
                0x06 => return Some("MOD"),
                0x07 => return Some("SMOD"),
                0x08 => return Some("ADDMOD"),
                0x09 => return Some("MULMOD"),
                0x0A => return Some("EXP"),
                _ => continue,
            }
        }
        
        None
    }
    
    /// Determine if the timestamp is used in a critical path
    fn is_critical_path(bytecode: &[u8]) -> bool {
        // Look for JUMPI within the next 10 opcodes
        for i in 0..std::cmp::min(10, bytecode.len()) {
            if bytecode[i] == 0x57 { // JUMPI
                return true;
            }
        }
        
        false
    }
    
    /// Determine severity based on the comparison operation
    fn determine_severity(comparison_op: &str) -> String {
        match comparison_op {
            "EQ" => "CRITICAL".to_string(),
            "LT" | "SLT" | "GT" | "SGT" => "HIGH".to_string(),
            _ => "MEDIUM".to_string()
        }
    }
}

/// Check if timestamp equality comparison is actually dangerous
fn is_dangerous_timestamp_equality(bytecode: &[u8], timestamp_pos: usize) -> bool {
    // Look for patterns that indicate REAL vulnerability:
    // 1. Timestamp equality used for access control
    // 2. Timestamp equality affecting financial operations
    // 3. Timestamp equality in critical state changes
    
    let search_window = 30;
    let start = timestamp_pos.saturating_sub(search_window);
    let end = std::cmp::min(timestamp_pos + search_window, bytecode.len());
    
    for i in start..end {
        if i >= bytecode.len() { continue; }
        
        match bytecode[i] {
            // Access control patterns
            0x33 => { // CALLER - access control
                // Check if timestamp equality affects caller-based logic
                if has_conditional_flow_after(bytecode, i) { return true; }
            },
            // Financial operations
            0xF1 | 0xF2 => { // CALL operations with value
                // Check if timestamp affects financial transfers
                if is_value_transfer(bytecode, i) { return true; }
            },
            // Storage operations
            0x55 => return true, // SSTORE - state changes based on exact timestamp
            // Self-destruct
            0xFF => return true, // SELFDESTRUCT - critical operation
            _ => {}
        }
    }
    
    // Check for auction/bidding patterns (common vulnerability)
    is_auction_pattern(bytecode, timestamp_pos)
}

/// Check if timestamp dependency is actually vulnerable
fn is_vulnerable_timestamp_dependency(bytecode: &[u8], timestamp_pos: usize, op_type: &str) -> bool {
    // Only flag timestamp dependencies that are actually exploitable:
    // 1. Used in randomness generation
    // 2. Used in critical financial logic
    // 3. Used without proper bounds/delays
    
    match op_type {
        "LT" | "GT" => {
            // Range comparisons are generally safer, only flag if critical
            is_critical_timestamp_range(bytecode, timestamp_pos)
        },
        _ => {
            // Other comparisons - check for vulnerability patterns
            has_vulnerable_timestamp_usage(bytecode, timestamp_pos)
        }
    }
}

/// Check for critical timestamp range usage
fn is_critical_timestamp_range(bytecode: &[u8], timestamp_pos: usize) -> bool {
    // Look for patterns that indicate vulnerable range usage:
    // 1. Very short time windows (< 1 minute)
    // 2. Range used in financial operations without delays
    
    let search_range = 20;
    for i in (timestamp_pos.saturating_sub(search_range))..timestamp_pos {
        if i >= bytecode.len() { continue; }
        
        // Look for small time constants (vulnerable)
        if bytecode[i] == 0x60 && i + 1 < bytecode.len() { // PUSH1
            let value = bytecode[i + 1];
            if value > 0 && value < 60 { // Less than 60 seconds - dangerous
                return true;
            }
        }
    }
    
    false
}

/// Check for vulnerable timestamp usage patterns
fn has_vulnerable_timestamp_usage(bytecode: &[u8], timestamp_pos: usize) -> bool {
    // Look for patterns that indicate real vulnerability:
    // 1. Randomness generation using timestamp
    // 2. Auction/bidding logic
    // 3. Time-locked operations without proper delays
    
    let window = 25;
    for i in (timestamp_pos.saturating_sub(window))..std::cmp::min(timestamp_pos + window, bytecode.len()) {
        if i >= bytecode.len() { continue; }
        
        match bytecode[i] {
            // Randomness patterns
            0x20 => return true, // SHA3/KECCAK256 - often used with timestamp for "randomness"
            0x44 => return true, // DIFFICULTY - combined with timestamp for randomness
            // Modulo operations (randomness)
            0x06 => return true, // MOD - timestamp % something = "random"
            _ => {}
        }
    }
    
    false
}

/// Helper: Check if there's conditional flow after an opcode
fn has_conditional_flow_after(bytecode: &[u8], pos: usize) -> bool {
    for i in pos..std::cmp::min(pos + 15, bytecode.len()) {
        if bytecode[i] == 0x57 { // JUMPI
            return true;
        }
    }
    false
}

/// Helper: Check if CALL operation involves value transfer
fn is_value_transfer(bytecode: &[u8], call_pos: usize) -> bool {
    // Look back for non-zero value being pushed before CALL
    for i in (call_pos.saturating_sub(10))..call_pos {
        if i >= bytecode.len() { continue; }
        
        if bytecode[i] >= 0x60 && bytecode[i] <= 0x7F { // PUSH operations
            let push_size = (bytecode[i] - 0x60 + 1) as usize;
            if i + push_size < bytecode.len() {
                // Check if any pushed value is non-zero
                for j in 1..=push_size {
                    if i + j < bytecode.len() && bytecode[i + j] != 0 {
                        return true; // Non-zero value = potential transfer
                    }
                }
            }
        }
    }
    false
}

/// Helper: Check for auction/bidding patterns
fn is_auction_pattern(bytecode: &[u8], timestamp_pos: usize) -> bool {
    // Look for patterns that suggest auction logic:
    // timestamp == deadline type comparisons
    
    let window = 30;
    let mut found_deadline = false;
    
    for i in (timestamp_pos.saturating_sub(window))..std::cmp::min(timestamp_pos + window, bytecode.len()) {
        if i >= bytecode.len() { continue; }
        
        // Look for storage loads (auction deadline storage)
        if bytecode[i] == 0x54 { // SLOAD
            found_deadline = true;
        }
        
        // Combined with financial operations
        if found_deadline && (bytecode[i] == 0xF1 || bytecode[i] == 0x55) {
            return true; // Auction pattern detected
        }
    }
    
    false
}
