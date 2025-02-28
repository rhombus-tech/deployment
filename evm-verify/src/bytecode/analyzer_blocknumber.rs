// Block Number Dependency Analyzer
//
// This module provides functionality to detect block number dependencies in EVM bytecode.
// Block number dependencies can cause issues with cross-chain compatibility and L2 chains.

use crate::bytecode::types::{AnalysisResults, BlockNumberDependency};
use crate::bytecode::opcodes::{Opcode, NUMBER};
use anyhow::Result;

/// Block number dependency detector
pub struct BlockNumberDependencyDetector;

impl BlockNumberDependencyDetector {
    /// Detect block number dependencies in bytecode
    pub fn detect(bytecode: &[u8], results: &mut AnalysisResults) -> Result<()> {
        // Initialize block number dependencies vector if empty
        if results.block_number_dependencies.is_empty() {
            results.block_number_dependencies = Vec::new();
        }
        
        // Scan bytecode for NUMBER opcode (0x43)
        for i in 0..bytecode.len() {
            if bytecode[i] == NUMBER {
                // Look ahead for comparison operations
                if let Some(comparison_op) = Self::find_comparison_after_number(&bytecode[i+1..]) {
                    // Found a block number comparison
                    results.block_number_dependencies.push(BlockNumberDependency {
                        offset: i,
                        dependency_type: "comparison".to_string(),
                        operation: comparison_op.to_string(),
                        is_critical: Self::is_critical_path(&bytecode[i+1..]),
                        severity: Self::determine_severity(comparison_op),
                    });
                    
                    // Add a warning about block number dependency
                    results.warnings.push(format!(
                        "Block number dependency detected at offset {}. This may cause issues with cross-chain compatibility, especially on L2 chains.",
                        i
                    ));
                }
                
                // Look for arithmetic operations
                if let Some(arithmetic_op) = Self::find_arithmetic_after_number(&bytecode[i+1..]) {
                    // Found a block number arithmetic operation
                    results.block_number_dependencies.push(BlockNumberDependency {
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
    
    /// Find comparison operations after NUMBER opcode
    fn find_comparison_after_number(bytecode: &[u8]) -> Option<&'static str> {
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
    
    /// Find arithmetic operations after NUMBER opcode
    fn find_arithmetic_after_number(bytecode: &[u8]) -> Option<&'static str> {
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
    
    /// Determine if the block number is used in a critical path
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
            "EQ" => "high".to_string(),   // Exact equality is problematic for L2 chains
            "LT" | "GT" => "high".to_string(), // Less than or greater than is problematic
            _ => "medium".to_string(),    // Other comparisons are medium severity
        }
    }
}
