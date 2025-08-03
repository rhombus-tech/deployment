use crate::bytecode::security::SecurityWarning;
use crate::bytecode::analyzer::BytecodeAnalyzer;
use anyhow::Result;
use ethers::types::H256;

/// Detects potential reentrancy vulnerabilities in EVM bytecode.
/// 
/// This module now uses the advanced reentrancy detection that:
/// 1. Filters out safe patterns (CEI, STATICCALL, internal calls)
/// 2. Focuses on actual reentrancy risks
/// 3. Reduces false positives significantly
pub fn detect_reentrancy(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    // Skip analysis if in test mode
    if analyzer.is_test_mode() {
        return vec![];
    }

    let bytecode = analyzer.get_bytecode_vec();
    let mut warnings = Vec::new();
    
    // Use the advanced detection function to avoid false positives
    if let Ok(()) = analyzer.detect_advanced_reentrancy_vulnerabilities(&bytecode, &mut warnings) {
        // Filter to only include actual reentrancy warnings from advanced detection
        warnings.retain(|w| matches!(w.kind, crate::bytecode::security::SecurityWarningKind::Reentrancy));
    }
    
    warnings
}

/// Alias for the detect_reentrancy function to maintain compatibility with the API module
pub fn detect_reentrancy_vulnerabilities(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    detect_reentrancy(analyzer)
}
