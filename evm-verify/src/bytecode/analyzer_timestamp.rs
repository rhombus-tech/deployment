// Timestamp Dependency Analyzer
//
// This module provides functionality to detect timestamp dependencies in EVM bytecode.
// Timestamp dependencies can be exploited by miners to manipulate contract execution.

use crate::bytecode::types::{AnalysisResults, TimestampDependency};
use crate::bytecode::opcodes::{Opcode, TIMESTAMP};
use anyhow::Result;

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
