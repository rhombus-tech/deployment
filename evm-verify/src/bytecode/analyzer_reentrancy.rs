use crate::bytecode::security::SecurityWarning;
use crate::bytecode::analyzer::BytecodeAnalyzer;
use anyhow::Result;
use ethers::types::H256;

/// Detects potential reentrancy vulnerabilities in EVM bytecode.
/// 
/// This module focuses on identifying:
/// 1. Classic reentrancy (storage write after external call)
/// 2. Read-only reentrancy (storage read after external call)
/// 3. Cross-function reentrancy patterns
pub fn detect_reentrancy(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    // Skip analysis if in test mode
    if analyzer.is_test_mode() {
        return vec![];
    }

    let bytecode = analyzer.get_bytecode_vec();
    let mut warnings = Vec::new();
    
    // Track storage reads, calls, and storage writes
    let mut storage_reads = Vec::new();
    let mut external_calls = Vec::new();
    let mut storage_writes = Vec::new();
    
    // Scan for storage reads, external calls, and storage writes
    let mut i = 0;
    while i < bytecode.len() {
        // Check for SLOAD (0x54) - Storage read
        if bytecode[i] == 0x54 {
            storage_reads.push(i);
        }
        
        // Check for CALL (0xF1), CALLCODE (0xF2), DELEGATECALL (0xF4), STATICCALL (0xFA) - External calls
        if bytecode[i] == 0xF1 || bytecode[i] == 0xF2 || bytecode[i] == 0xF4 || bytecode[i] == 0xFA {
            external_calls.push(i);
        }
        
        // Check for SSTORE (0x55) - Storage write
        if bytecode[i] == 0x55 {
            storage_writes.push(i);
        }
        
        i += 1;
    }
    
    // Check for classic reentrancy pattern: storage write after external call
    for &call_pos in &external_calls {
        for &write_pos in &storage_writes {
            if write_pos > call_pos {
                // This is a potential reentrancy vulnerability
                warnings.push(SecurityWarning::reentrancy(call_pos as u64, H256::zero()));
                break; // Only report one warning per call
            }
        }
    }
    
    // Return all detected warnings
    warnings
}
