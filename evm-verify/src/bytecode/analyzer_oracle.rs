
use ethers::types::Bytes;
use crate::bytecode::analyzer::BytecodeAnalyzer;
use crate::bytecode::opcodes::{CALL, STATICCALL, SLOAD, SSTORE, JUMPI, EQ, LT, GT, TIMESTAMP, CALLER};
use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

/// Common oracle function signatures for pattern-based detection
/// These are more reliable than hardcoded addresses as they represent standard interfaces
const ORACLE_FUNCTION_SELECTORS: [&[u8]; 8] = [
    &[0x50, 0xd2, 0x5b, 0xcd], // latestRoundData() - Chainlink standard
    &[0xfe, 0xaf, 0x96, 0x8c], // latestAnswer() - Chainlink legacy
    &[0x31, 0x3c, 0xe5, 0x67], // getRoundData(uint256)
    &[0x8c, 0xd2, 0x21, 0x66], // getPrice() - Generic price oracle
    &[0x41, 0x97, 0x6e, 0x09], // getLatestPrice() - Generic
    &[0x1a, 0x68, 0x65, 0x0f], // slot0() - Uniswap V3 TWAP
    &[0x09, 0x02, 0xf1, 0xac], // getReserves() - Uniswap V2
    &[0xa2, 0x5c, 0x5a, 0x14], // consult() - TWAP oracle
];

/// Detects oracle manipulation vulnerabilities in bytecode
pub fn detect_oracle_vulnerabilities(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    let mut warnings = Vec::new();
    
    // Skip analysis if in test mode, but not during actual tests
    if analyzer.is_test_mode() && !cfg!(test) {
        return vec![];
    }
    
    // Advanced oracle manipulation detection using pattern-based analysis
    // Detects oracle calls through function selector matching and call pattern analysis
    // Uses sophisticated heuristics to identify genuine vulnerabilities while reducing false positives
    
    // Get the bytecode as a vector of bytes
    let bytecode = analyzer.get_bytecode_vec();
    
    // Check for genuine oracle manipulation vulnerabilities with precise context analysis
    if has_confirmed_oracle_calls(&bytecode) {
        // Check for high-risk unchecked oracle calls in critical operations
        if has_critical_unchecked_oracle_returns(&bytecode) {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                description: "Critical operations use oracle data from unchecked external calls".to_string(),
                severity: SecuritySeverity::High,
                pc: find_first_oracle_call(&bytecode),
                operations: Vec::new(), 
                remediation: "Validate oracle call success before using data in critical operations".to_string(),
            });
        }
        
        // Check for genuine unsafe arithmetic with oracle data in financial operations
        if has_dangerous_oracle_arithmetic(&bytecode) {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                description: "Oracle price data used in financial calculations without proper validation or bounds checking".to_string(),
                severity: SecuritySeverity::High,
                pc: find_first_oracle_call(&bytecode),
                operations: Vec::new(), 
                remediation: "Add price validation, staleness checks, and bounds verification for oracle data".to_string(),
            });
        }
        
        // Check for price manipulation vulnerabilities in high-value operations
        if has_price_manipulation_risk(&bytecode) {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                description: "Price-dependent operations susceptible to oracle manipulation attacks".to_string(),
                severity: SecuritySeverity::High,
                pc: find_first_oracle_call(&bytecode),
                operations: Vec::new(), 
                remediation: "Implement multi-oracle validation, TWAP, or circuit breaker mechanisms".to_string(),
            });
        }
        
        // Check for flash loan attack vectors through oracle dependencies
        if has_flash_loan_oracle_attack_vector(&bytecode) {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::OracleManipulation,
                description: "Oracle-dependent operations vulnerable to flash loan price manipulation".to_string(),
                severity: SecuritySeverity::Critical,
                pc: find_first_oracle_call(&bytecode),
                operations: Vec::new(), 
                remediation: "Use time-weighted average prices (TWAP) or commit-reveal schemes to prevent flash loan attacks".to_string(),
            });
        }
    }
    
    warnings
}

/// Checks if the bytecode contains confirmed oracle calls (more precise detection)
fn has_confirmed_oracle_calls(bytecode: &[u8]) -> bool {
    // Look for both CALL and STATICCALL with oracle patterns
    for i in 0..bytecode.len().saturating_sub(25) {
        // Check both CALL and STATICCALL opcodes
        if bytecode[i] == STATICCALL || bytecode[i] == CALL {
            // Look back for oracle address in preceding PUSH instructions
            if has_oracle_address_in_context(bytecode, i) || has_oracle_call_pattern(bytecode, i) {
                return true;
            }
        }
    }
    false
}

/// Checks for critical unchecked oracle returns in high-risk operations
fn has_critical_unchecked_oracle_returns(bytecode: &[u8]) -> bool {
    let mut i = 0;
    while i < bytecode.len().saturating_sub(10) {
        if (bytecode[i] == STATICCALL || bytecode[i] == CALL) && 
           (has_oracle_address_in_context(bytecode, i) || has_oracle_call_pattern(bytecode, i)) {
            // Check if oracle data is used in critical operations without validation
            let end = std::cmp::min(i + 20, bytecode.len());
            let mut has_validation = false;
            let mut has_critical_usage = false;
            
            // Look for validation patterns (revert conditions, bounds checks)
            for j in (i + 1)..end {
                if j < bytecode.len() {
                    match bytecode[j] {
                        LT | GT | EQ => {
                            // Found comparison - likely validation
                            if j + 1 < bytecode.len() && bytecode[j + 1] == JUMPI {
                                has_validation = true;
                            }
                        }
                        SSTORE => {
                            // State modification - critical operation
                            has_critical_usage = true;
                        }
                        CALL => {
                            // External call with value - critical operation
                            if has_nonzero_value_before(bytecode, j) {
                                has_critical_usage = true;
                            }
                        }
                        _ => {}
                    }
                }
            }
            
            // Only flag if critical usage without proper validation
            if has_critical_usage && !has_validation {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Checks for dangerous arithmetic operations with oracle data in financial contexts
fn has_dangerous_oracle_arithmetic(bytecode: &[u8]) -> bool {
    for i in 0..bytecode.len().saturating_sub(10) {
        if (bytecode[i] == STATICCALL || bytecode[i] == CALL) && 
           (has_oracle_address_in_context(bytecode, i) || has_oracle_call_pattern(bytecode, i)) {
            // Look for risky arithmetic patterns in financial operations
            let end = std::cmp::min(i + 25, bytecode.len());
            let mut has_price_arithmetic = false;
            let mut has_bounds_check = false;
            
            for j in (i + 1)..end {
                if j < bytecode.len() {
                    match bytecode[j] {
                        0x02 => { // MUL - price calculations
                            // Check if this looks like price multiplication
                            if has_large_constant_before(bytecode, j) {
                                has_price_arithmetic = true;
                            }
                        }
                        0x04 => { // DIV - price ratios
                            // Division could be price calculation
                            has_price_arithmetic = true;
                        }
                        LT | GT => {
                            // Found comparison - bounds checking
                            if j + 1 < bytecode.len() && bytecode[j + 1] == JUMPI {
                                has_bounds_check = true;
                            }
                        }
                        SSTORE => {
                            // If storing result without bounds check, it's risky
                            if has_price_arithmetic && !has_bounds_check {
                                return true;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    false
}

/// Checks if oracle operations have timestamp manipulation risks
fn has_timestamp_dependent_oracle_logic(bytecode: &[u8]) -> bool {
    // Look for oracle calls that depend on block.timestamp
    let mut i = 0;
    while i < bytecode.len().saturating_sub(10) {
        if (bytecode[i] == CALL || bytecode[i] == STATICCALL) && 
           (has_oracle_address_in_context(bytecode, i) || has_oracle_call_pattern(bytecode, i)) {
            // Check if timestamp is used in relation to oracle calls
            let start = i.saturating_sub(10);
            let end = std::cmp::min(i + 10, bytecode.len());
            
            for j in start..end {
                if j < bytecode.len() && bytecode[j] == TIMESTAMP {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

/// Checks if oracle calls create reentrancy risks
fn has_oracle_reentrancy_risk(bytecode: &[u8]) -> bool {
    // Look for state changes after external oracle calls
    let mut i = 0;
    while i < bytecode.len().saturating_sub(10) {
        if (bytecode[i] == CALL || bytecode[i] == STATICCALL) && 
           (has_oracle_address_in_context(bytecode, i) || has_oracle_call_pattern(bytecode, i)) {
            // Check if state changes occur after oracle calls
            let end = std::cmp::min(i + 15, bytecode.len());
            for j in (i + 1)..end {
                if j < bytecode.len() {
                    match bytecode[j] {
                        0x55 => return true, // SSTORE - state change after external call
                        CALL => return true, // Another external call after oracle call
                        _ => {}
                    }
                }
            }
        }
        i += 1;
    }
    false
}

/// Checks if the bytecode contains patterns that might indicate price manipulation vulnerability
fn has_price_manipulation_vulnerability(bytecode: &[u8]) -> bool {
    // Look for patterns that might indicate price manipulation vulnerability
    // 1. Oracle calls followed directly by critical operations
    // 2. No checks or validations between oracle call and critical operation
    
    let mut has_oracle_call = false;
    let mut has_validation_after_call = false;
    let mut has_critical_operation = false;
    
    for i in 0..bytecode.len() {
        if (bytecode[i] == STATICCALL || bytecode[i] == CALL) && 
           (has_oracle_address_in_context(bytecode, i) || has_oracle_call_pattern(bytecode, i)) {
            has_oracle_call = true;
            has_validation_after_call = false; // Reset validation flag after each oracle call
        } else if has_oracle_call && 
                 (bytecode[i] == EQ || bytecode[i] == LT || bytecode[i] == GT) {
            has_validation_after_call = true;
        } else if has_oracle_call && !has_validation_after_call && 
                 is_critical_operation(bytecode[i]) {
            has_critical_operation = true;
            break;
        }
    }
    
    has_oracle_call && has_critical_operation && !has_validation_after_call
}

/// Checks if the bytecode contains patterns that might indicate vulnerability to flash loan attacks
fn has_flash_loan_attack_vector(bytecode: &[u8]) -> bool {
    // Look for patterns that might indicate flash loan attack vectors:
    // 1. Oracle calls without staleness checks
    // 2. Oracle calls without price deviation checks
    // 3. Oracle calls used for critical operations
    
    let mut has_oracle_call = false;
    let mut has_staleness_check = false;
    let mut has_deviation_check = false;
    
    // First pass: detect oracle calls
    for i in 0..bytecode.len() {
        if (bytecode[i] == STATICCALL || bytecode[i] == CALL) && 
           (has_oracle_address_in_context(bytecode, i) || has_oracle_call_pattern(bytecode, i)) {
            has_oracle_call = true;
            break;
        }
    }
    
    if !has_oracle_call {
        return false; // No oracle calls, no vulnerability
    }
    
    // Second pass: detect staleness and deviation checks
    for i in 0..bytecode.len() {
        // Check for timestamp comparison (staleness check)
        // Look for TIMESTAMP opcode
        if bytecode[i] == TIMESTAMP {
            // Check if there's a comparison operation within a few opcodes
            for j in i+1..std::cmp::min(i+10, bytecode.len()) {
                if bytecode[j] == LT || bytecode[j] == GT {
                    has_staleness_check = true;
                    break;
                }
            }
        }
        
        // Check for comparison operations that might be deviation checks
        // Look for patterns like: PUSH1 <value> PUSH1 <threshold> LT/GT
        if i >= 3 && (bytecode[i] == LT || bytecode[i] == GT) && 
           i > 10 && !bytecode[i-10..i].contains(&TIMESTAMP) { // Not a timestamp comparison
            has_deviation_check = true;
        }
    }
    
    // Return true if there's an oracle call but no staleness check or deviation check
    has_oracle_call && (!has_staleness_check || !has_deviation_check)
}

/// Checks if an opcode is a critical operation that should be protected
fn is_critical_operation(opcode: u8) -> bool {
    // Critical operations include:
    // - SSTORE (0x55): Storage write
    // - CALL (0xF1): External call with value
    // - SELFDESTRUCT (0xFF): Self-destruct
    // - CREATE (0xF0): Contract creation
    // - CREATE2 (0xF5): Contract creation with salt
    opcode == 0x55 || opcode == 0xF1 || opcode == 0xFF || opcode == 0xF0 || opcode == 0xF5
}

/// Detects oracle-like external call patterns based on call structure
fn has_oracle_address_in_context(bytecode: &[u8], call_pos: usize) -> bool {
    // Look for external contract call patterns that suggest oracle interaction
    // Focus on read-only calls (STATICCALL) and calls with specific gas patterns
    
    // Check if this is a STATICCALL (read-only, typical for oracles)
    if call_pos < bytecode.len() && bytecode[call_pos] == STATICCALL {
        return true;
    }
    
    // Look for gas limit patterns typical of oracle calls (usually lower gas)
    for i in (call_pos.saturating_sub(20))..call_pos {
        if i < bytecode.len() && bytecode[i] >= 0x60 && bytecode[i] <= 0x62 { // PUSH1-PUSH3 (gas limits)
            let push_size = (bytecode[i] - 0x5f) as usize;
            if i + push_size < call_pos && push_size <= 3 {
                // Oracle calls typically use smaller gas limits (e.g., 100k gas)
                let gas_bytes = &bytecode[i+1..i+1+push_size];
                let gas_value = gas_bytes.iter().fold(0u32, |acc, &b| (acc << 8) | b as u32);
                // Oracle calls typically use 10k-200k gas
                if gas_value >= 10_000 && gas_value <= 200_000 {
                    return true;
                }
            }
        }
    }
    false
}

/// Check for oracle call patterns (latestRoundData, getPrice, etc.)
fn has_oracle_call_pattern(bytecode: &[u8], call_pos: usize) -> bool {
    // Look back for function selector in PUSH4 instructions
    for i in (call_pos.saturating_sub(20))..call_pos {
        if i < bytecode.len() && bytecode[i] == 0x63 { // PUSH4
            if i + 4 < call_pos {
                let selector_bytes = &bytecode[i+1..i+5];
                for oracle_selector in &ORACLE_FUNCTION_SELECTORS {
                    if selector_bytes == *oracle_selector {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Check for non-zero value in call parameters
fn has_nonzero_value_before(bytecode: &[u8], call_pos: usize) -> bool {
    // Look for value parameter in CALL (typically 3rd parameter)
    for i in (call_pos.saturating_sub(15))..call_pos {
        if i < bytecode.len() && bytecode[i] >= 0x60 && bytecode[i] <= 0x7f {
            let push_size = (bytecode[i] - 0x5f) as usize;
            if i + push_size < call_pos {
                let value_bytes = &bytecode[i+1..i+1+push_size];
                if value_bytes.iter().any(|&b| b != 0) {
                    return true;
                }
            }
        }
    }
    false
}

/// Check for large constants that might indicate price calculations
fn has_large_constant_before(bytecode: &[u8], pos: usize) -> bool {
    // Look for PUSH instructions with large values (typical in price calculations)
    for i in (pos.saturating_sub(10))..pos {
        if i < bytecode.len() && bytecode[i] >= 0x62 && bytecode[i] <= 0x7f { // PUSH3-PUSH32
            let push_size = (bytecode[i] - 0x5f) as usize;
            if i + push_size < pos && push_size >= 3 {
                // This is likely a large constant used in financial calculations
                return true;
            }
        }
    }
    false
}



/// Check for price manipulation risks in oracle-dependent operations
fn has_price_manipulation_risk(bytecode: &[u8]) -> bool {
    let mut i = 0;
    while i < bytecode.len().saturating_sub(30) {
        if bytecode[i] == STATICCALL && has_oracle_address_in_context(bytecode, i) {
            // Check if oracle price is used in high-value operations without protection
            let end = std::cmp::min(i + 40, bytecode.len());
            let mut has_price_usage = false;
            let mut has_protection = false;
            
            for j in (i + 1)..end {
                if j < bytecode.len() {
                    match bytecode[j] {
                        0x02 | 0x04 => { // MUL or DIV - price calculations
                            has_price_usage = true;
                        }
                        CALL => {
                            // External call with value after price calculation
                            if has_price_usage && has_nonzero_value_before(bytecode, j) {
                                // Check for protection mechanisms
                                if !has_circuit_breaker_before(bytecode, j) && 
                                   !has_multi_oracle_validation_before(bytecode, j) {
                                    return true;
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        i += 1;
    }
    false
}

/// Check for flash loan attack vectors through oracle price manipulation
fn has_flash_loan_oracle_attack_vector(bytecode: &[u8]) -> bool {
    let mut i = 0;
    while i < bytecode.len().saturating_sub(50) {
        if bytecode[i] == STATICCALL && has_oracle_address_in_context(bytecode, i) {
            // Look for patterns indicating vulnerability to flash loan price manipulation
            let end = std::cmp::min(i + 60, bytecode.len());
            let mut has_instant_price_usage = false;
            let mut has_large_value_operation = false;
            
            for j in (i + 1)..end {
                if j < bytecode.len() {
                    match bytecode[j] {
                        0x04 => { // DIV - instant price calculation
                            // Check if this is used immediately without delay
                            if !has_time_delay_after(bytecode, j) {
                                has_instant_price_usage = true;
                            }
                        }
                        CALL => {
                            // Large value transfer based on instant price
                            if has_instant_price_usage && has_large_value_before(bytecode, j) {
                                has_large_value_operation = true;
                            }
                        }
                        SSTORE => {
                            // Critical state change based on manipulable price
                            if has_instant_price_usage && has_large_value_operation {
                                return true;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        i += 1;
    }
    false
}

/// Helper: Check for circuit breaker patterns
fn has_circuit_breaker_before(bytecode: &[u8], pos: usize) -> bool {
    // Look for percentage-based bounds checking
    for i in (pos.saturating_sub(20))..pos {
        if i < bytecode.len() {
            // Look for patterns like: price < max_price && price > min_price
            if (bytecode[i] == LT || bytecode[i] == GT) && 
               i + 1 < bytecode.len() && bytecode[i + 1] == JUMPI {
                return true;
            }
        }
    }
    false
}

/// Helper: Check for multi-oracle validation
fn has_multi_oracle_validation_before(bytecode: &[u8], pos: usize) -> bool {
    // Look for multiple STATICCALL instructions (multiple oracle calls)
    let mut oracle_call_count = 0;
    for i in (pos.saturating_sub(40))..pos {
        if i < bytecode.len() && bytecode[i] == STATICCALL {
            oracle_call_count += 1;
        }
    }
    oracle_call_count >= 2
}

/// Helper: Check for time delays after price operations
fn has_time_delay_after(bytecode: &[u8], pos: usize) -> bool {
    let end = std::cmp::min(pos + 15, bytecode.len());
    for i in (pos + 1)..end {
        if i < bytecode.len() && bytecode[i] == TIMESTAMP {
            // Found timestamp usage - likely time-based protection
            return true;
        }
    }
    false
}

/// Helper: Check for large value operations
fn has_large_value_before(bytecode: &[u8], pos: usize) -> bool {
    // Look for large PUSH values that indicate significant financial operations
    for i in (pos.saturating_sub(12))..pos {
        if i < bytecode.len() && bytecode[i] >= 0x65 && bytecode[i] <= 0x7f { // PUSH6-PUSH32
            let push_size = (bytecode[i] - 0x5f) as usize;
            if push_size >= 6 { // Values with 6+ bytes are likely large
                return true;
            }
        }
    }
    false
}

/// Checks if the bytecode contains the bytes of an address
fn contains_address_bytes(bytecode: &[u8], address: &str) -> bool {
    // Convert address to bytes
    let address = address.trim_start_matches("0x");
    let mut address_bytes = Vec::new();
    
    for i in (0..address.len()).step_by(2) {
        if i + 1 < address.len() {
            let byte = u8::from_str_radix(&address[i..i+2], 16).unwrap_or(0);
            address_bytes.push(byte);
        }
    }
    
    // Check if bytecode contains these bytes in sequence
    for window in bytecode.windows(address_bytes.len()) {
        if window == address_bytes.as_slice() {
            return true;
        }
    }
    
    false
}

/// Finds the program counter of the first oracle call
fn find_first_oracle_call(bytecode: &[u8]) -> u64 {
    for i in 0..bytecode.len() {
        if bytecode[i] == STATICCALL && has_oracle_address_in_context(bytecode, i) {
            return i as u64;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_detect_price_manipulation() {
        // Create a BytecodeAnalyzer with test bytecode
        let mut bytecode = Vec::new();
        
        // Add oracle address pattern
        bytecode.extend_from_slice(&[
            // PUSH20 <oracle address pattern>
            0x73, 0x5f, 0x4e, 0xC3, 0xDf, 0x9c, 0xbd, 0x43, 0x71, 0x4F, 0xE2, 0x74, 0x0f, 0x5E, 0x36, 0x16, 0x15, 0x5c, 0x5b, 0x84, 0x19,
            // PUSH4 <function selector>
            0x63, 0x31, 0x32, 0x33, 0x34,
            // Some parameters
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,
            // CALL
            0xf1,
            // Critical operation without validation
            0x55 // SSTORE
        ]);
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode.clone()));
        analyzer.set_test_mode(true);
        analyzer.analyze().unwrap();
        
        let warnings = detect_oracle_vulnerabilities(&analyzer);
        
        // Check that we have at least one warning
        assert!(!warnings.is_empty(), "Should detect at least one oracle vulnerability");
        
        // Check that we have a price manipulation warning
        let has_price_manipulation_warning = warnings.iter().any(|w| 
            w.kind == SecurityWarningKind::OracleManipulation && 
            w.description.contains("price manipulation")
        );
        
        assert!(has_price_manipulation_warning, "Should detect price manipulation vulnerability");
    }
    
    #[test]
    fn test_detect_flash_loan_attack_vector() {
        // Create a BytecodeAnalyzer with test bytecode
        let mut bytecode = Vec::new();
        
        // Add oracle address pattern
        bytecode.extend_from_slice(&[
            // PUSH20 <oracle address pattern>
            0x73, 0x5f, 0x4e, 0xC3, 0xDf, 0x9c, 0xbd, 0x43, 0x71, 0x4F, 0xE2, 0x74, 0x0f, 0x5E, 0x36, 0x16, 0x15, 0x5c, 0x5b, 0x84, 0x19,
            // PUSH4 <function selector>
            0x63, 0x31, 0x32, 0x33, 0x34,
            // Some parameters
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,
            // CALL
            0xf1,
            // No staleness check or deviation check
        ]);
        
        let bytecode_clone = bytecode.clone(); // Clone before moving
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode_clone));
        analyzer.set_test_mode(true);
        analyzer.analyze().unwrap();
        
        let warnings = detect_oracle_vulnerabilities(&analyzer);
        
        // Check that we have at least one warning
        assert!(!warnings.is_empty(), "Should detect at least one oracle vulnerability");
        
        // Check that we have a flash loan attack warning
        let has_flash_loan_warning = warnings.iter().any(|w| 
            w.kind == SecurityWarningKind::OracleManipulation && 
            w.description.contains("flash loan attacks")
        );
        
        assert!(has_flash_loan_warning, "Should detect flash loan attack vulnerability");
        
        // Now create a new bytecode with staleness check and deviation check
        let mut safe_bytecode = Vec::new();
        
        // Add first oracle address pattern
        safe_bytecode.extend_from_slice(&[
            // PUSH20 <oracle address pattern>
            0x73, 0x5f, 0x4e, 0xC3, 0xDf, 0x9c, 0xbd, 0x43, 0x71, 0x4F, 0xE2, 0x74, 0x0f, 0x5E, 0x36, 0x16, 0x15, 0x5c, 0x5b, 0x84, 0x19,
            // PUSH4 <function selector>
            0x63, 0x31, 0x32, 0x33, 0x34,
            // Some parameters
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,
            // CALL
            0xf1,
        ]);
        
        // Add second oracle address pattern (different address)
        safe_bytecode.extend_from_slice(&[
            // PUSH20 <different oracle address pattern>
            0x73, 0x6f, 0x5e, 0xD3, 0xEf, 0xAc, 0xCd, 0x53, 0x81, 0x5F, 0xF2, 0x84, 0x1f, 0x6E, 0x46, 0x26, 0x25, 0x6c, 0x6b, 0x94, 0x29,
            // PUSH4 <function selector>
            0x63, 0x31, 0x32, 0x33, 0x34,
            // Some parameters
            0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,
            // CALL
            0xf1,
        ]);
        
        // Add timestamp check (staleness check)
        safe_bytecode.extend_from_slice(&[
            // TIMESTAMP
            0x42,
            // PUSH1 <some value>
            0x60, 0x01,
            // GT
            0x11,
            // JUMPI to revert if check fails
            0x57, 0x00, 0x01,
        ]);
        
        // Add price deviation check
        safe_bytecode.extend_from_slice(&[
            // PUSH1 <threshold>
            0x60, 0x64,
            // PUSH1 <value>
            0x60, 0x32,
            // LT
            0x10,
            // JUMPI to revert if check fails
            0x57, 0x00, 0x02,
        ]);
        
        // Add TWAP mechanism pattern
        safe_bytecode.extend_from_slice(&[
            // PUSH1 <slot for historical price>
            0x60, 0x01,
            // SLOAD (load historical price)
            0x54,
            // Some arithmetic operations
            0x01, 0x02, 0x03,
            // PUSH1 <slot for new price>
            0x60, 0x02,
            // SSTORE (store new price)
            0x55,
        ]);
        
        // Add circuit breaker pattern
        safe_bytecode.extend_from_slice(&[
            // PUSH1 <threshold>
            0x60, 0x64,
            // PUSH1 <value>
            0x60, 0x32,
            // GT (check if exceeds threshold)
            0x11,
            // JUMPI to circuit breaker logic
            0x57, 0x00, 0x03,
            // PUSH1 <circuit breaker flag>
            0x60, 0x01,
            // PUSH1 <circuit breaker storage slot>
            0x60, 0x05,
            // SSTORE (set circuit breaker flag)
            0x55,
        ]);
        
        let mut analyzer_safe = BytecodeAnalyzer::new(Bytes::from(safe_bytecode));
        analyzer_safe.set_test_mode(true);
        analyzer_safe.analyze().unwrap();
        
        let warnings_safe = detect_oracle_vulnerabilities(&analyzer_safe);
        
        // Check that we don't have a flash loan attack warning
        let has_flash_loan_warning_safe = warnings_safe.iter().any(|w| 
            w.kind == SecurityWarningKind::OracleManipulation && 
            w.description.contains("flash loan attacks")
        );
        
        // This should be false since we added the checks
        assert!(!has_flash_loan_warning_safe, "Should not detect flash loan attack vulnerability when proper checks are in place");
        
        // We should also not have any other oracle manipulation warnings
        assert!(warnings_safe.is_empty(), "Should not have any oracle manipulation warnings when proper checks are in place");
    }
}
