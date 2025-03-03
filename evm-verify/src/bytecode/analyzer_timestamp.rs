// Timestamp Dependency Analyzer
//
// This module provides functionality to detect timestamp dependencies in EVM bytecode.
// Timestamp dependencies can be exploited by miners to manipulate contract execution.

use crate::bytecode::types::{AnalysisResults, TimestampDependency};
use crate::bytecode::opcodes::{Opcode, TIMESTAMP, LT, GT, SLT, SGT, EQ, ADD, MUL, SUB, DIV, MOD, JUMPI, JUMP};
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
                let abs_op_idx = i + 1 + op_idx;
                
                // Check if it's an equality comparison (more dangerous)
                if op_type == "EQ" {
                    warnings.push(SecurityWarning::new(
                        SecurityWarningKind::UnsafeTimestampComparison,
                        SecuritySeverity::Medium,
                        pc,
                        "Unsafe timestamp equality comparison detected. Exact timestamp matching can be manipulated by miners.".to_string(),
                        vec![Operation::Timestamp, Operation::Comparison { op_type: op_type.to_string() }],
                        "Use timestamp ranges (greater than, less than) instead of exact equality checks.".to_string()
                    ));
                } else {
                    // General timestamp comparison
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
                let abs_op_idx = i + 1 + op_idx;
                
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
                let abs_op_idx = i + 1 + op_idx;
                
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
            "EQ" => "high".to_string(),   // Exact equality is highly manipulable
            "LT" | "GT" => "high".to_string(), // Less than or greater than is manipulable
            _ => "medium".to_string(),    // Other comparisons are medium severity
        }
    }
}
