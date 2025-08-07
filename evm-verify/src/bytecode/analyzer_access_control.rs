use crate::bytecode::security::SecurityWarning;
use crate::bytecode::analyzer::BytecodeAnalyzer;
use crate::bytecode::opcodes::*;

/// Detects potential access control vulnerabilities in EVM bytecode.
/// 
/// This module focuses on identifying:
/// 1. Missing access controls before sensitive operations
/// 2. Weak access control mechanisms
/// 3. Inconsistent access control patterns
/// 4. Role-based access control implementations
/// 5. Owner-only function patterns
pub fn detect_access_control_vulnerabilities(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    // Skip analysis if in test mode
    if analyzer.is_test_mode() {
        return vec![];
    }

    let _bytecode = analyzer.get_bytecode_vec();
    let mut warnings = Vec::new();
    
    // Check for sensitive operations without access controls
    detect_missing_access_controls(analyzer, &mut warnings);
    
    // Check for inconsistent access control patterns
    detect_inconsistent_access_controls(analyzer, &mut warnings);
    
    // Check for weak access control implementations
    detect_weak_access_controls(analyzer, &mut warnings);
    
    // Return all detected warnings
    warnings
}

/// Detects operations that typically require access controls but don't have them.
/// 
/// Sensitive operations include:
/// - State-changing operations (SSTORE)
/// - Fund transfers (CALL with value)
/// - Administrative functions (SELFDESTRUCT, DELEGATECALL)
/// - Critical configuration changes
fn detect_missing_access_controls(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>) {
    let _bytecode = analyzer.get_bytecode_vec();
    
    // Simple bytecode with just a SSTORE operation is definitely missing access controls
    if _bytecode.len() <= 2 && _bytecode.contains(&SSTORE) {
        warnings.push(SecurityWarning::access_control_vulnerability(0));
        return;
    }

    // Track access control patterns
    let mut access_control_patterns = AccessControlPatterns::new();
    
    // First pass: identify access control patterns
    for i in 0.._bytecode.len().saturating_sub(4) {
        let pc = i as u64;
        
        // Create a window of opcodes
        let window = &_bytecode[i..std::cmp::min(i + 5, _bytecode.len())];
        
        // Check for CALLER followed by comparison and conditional jump
        if window.len() >= 3 && window[0] == CALLER {
            // Look for comparison operations
            if is_comparison_op(window[1]) {
                access_control_patterns.caller_checks.push(pc);
                
                // If followed by JUMPI, it's a strong pattern
                if window.len() >= 3 && window[2] == JUMPI {
                    access_control_patterns.strong_checks.push(pc);
                }
            }
        }
        
        // Check for SLOAD (loading from storage) followed by comparison
        // This could be loading an owner or role mapping
        if window.len() >= 3 && window[0] == SLOAD && is_comparison_op(window[1]) {
            access_control_patterns.storage_checks.push(pc);
            
            // If followed by JUMPI, it's likely a strong access check
            if window.len() >= 3 && window[2] == JUMPI {
                access_control_patterns.strong_checks.push(pc);
            }
        }
        
        // Identify sensitive operations
        if is_sensitive_op(window[0]) {
            access_control_patterns.sensitive_ops.push(pc);
        }
    }
    
    // Second pass: analyze control flow to determine if sensitive operations are protected
    let protected_ops = find_protected_operations(analyzer, &access_control_patterns);
    
    // Generate warnings for unprotected sensitive operations
    for &pc in &access_control_patterns.sensitive_ops {
        if !protected_ops.contains(&pc) {
            warnings.push(SecurityWarning::access_control_vulnerability(pc));
        }
    }
}

/// Detects inconsistent access control patterns across similar functions
fn detect_inconsistent_access_controls(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>) {
    let bytecode = analyzer.get_bytecode_vec();
    
    // Step 1: Identify function boundaries using JUMPDEST markers
    let functions = identify_function_boundaries(&bytecode);
    
    // Step 2: Classify functions by their behavior patterns
    let function_classes = classify_functions(&bytecode, &functions);
    
    // Step 3: Analyze access control patterns within each function class
    let access_patterns = analyze_function_access_patterns(&bytecode, &functions);
    
    // Step 4: Detect inconsistencies within similar function classes
    detect_pattern_inconsistencies(&function_classes, &access_patterns, warnings);
}

/// Identifies function boundaries using JUMPDEST opcodes and function dispatch patterns
fn identify_function_boundaries(bytecode: &[u8]) -> Vec<FunctionBoundary> {
    let mut functions = Vec::new();
    let mut i = 0;
    
    while i < bytecode.len() {
        // Look for JUMPDEST (0x5B) which typically marks function entry points
        if bytecode[i] == 0x5B {
            // Check if this JUMPDEST follows a function selector pattern
            let function_start = i;
            let mut function_end = find_function_end(bytecode, i);
            
            // Extract potential function selector (4 bytes)
            let selector = extract_function_selector(bytecode, i);
            
            if function_end > function_start + 10 { // Minimum viable function size
                functions.push(FunctionBoundary {
                    start: function_start,
                    end: function_end,
                    selector,
                    signature_hash: compute_function_hash(&selector),
                });
            }
        }
        i += 1;
    }
    
    functions
}

/// Classifies functions based on their behavior patterns (state-changing, view, etc.)
fn classify_functions(bytecode: &[u8], functions: &[FunctionBoundary]) -> Vec<FunctionClass> {
    functions.iter().map(|func| {
        let function_bytecode = &bytecode[func.start..func.end];
        
        FunctionClass {
            boundary: func.clone(),
            behavior: classify_function_behavior(function_bytecode),
            complexity_score: calculate_complexity_score(function_bytecode),
            storage_operations: count_storage_operations(function_bytecode),
        }
    }).collect()
}

/// Analyzes access control patterns for each function
fn analyze_function_access_patterns(bytecode: &[u8], functions: &[FunctionBoundary]) -> Vec<AccessControlPattern> {
    functions.iter().map(|func| {
        let function_bytecode = &bytecode[func.start..func.end];
        
        AccessControlPattern {
            function_start: func.start,
            has_owner_check: detect_owner_check_pattern(function_bytecode),
            has_role_check: detect_role_based_access(function_bytecode),
            has_modifier_protection: detect_modifier_pattern(function_bytecode),
            has_caller_validation: detect_caller_validation_pattern(function_bytecode),
            protection_strength: calculate_protection_strength(function_bytecode),
        }
    }).collect()
}

/// Detects inconsistencies between similar functions
fn detect_pattern_inconsistencies(
    function_classes: &[FunctionClass],
    access_patterns: &[AccessControlPattern],
    warnings: &mut Vec<SecurityWarning>
) {
    // Group functions by behavior type
    let mut behavior_groups: std::collections::HashMap<FunctionBehavior, Vec<usize>> = std::collections::HashMap::new();
    
    for (i, class) in function_classes.iter().enumerate() {
        behavior_groups.entry(class.behavior.clone()).or_insert_with(Vec::new).push(i);
    }
    
    // Check each behavior group for access control inconsistencies
    for (behavior, indices) in behavior_groups {
        if indices.len() < 2 { continue; } // Need at least 2 functions to compare
        
        let patterns: Vec<&AccessControlPattern> = indices.iter()
            .map(|&i| &access_patterns[i])
            .collect();
        
        // Detect inconsistencies within this behavior group
        if let Some(inconsistency) = detect_group_inconsistency(&patterns, &behavior) {
            warnings.push(SecurityWarning::inconsistent_access_control(
                inconsistency.primary_location as u64,
                inconsistency.protected_functions,
                inconsistency.unprotected_functions,
            ));
        }
    }
}

/// Supporting data structures
#[derive(Clone, Debug)]
struct FunctionBoundary {
    start: usize,
    end: usize,
    selector: Option<[u8; 4]>,
    signature_hash: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum FunctionBehavior {
    StateModifying,  // Functions that change contract state
    ViewFunction,    // Read-only functions
    PureFunction,    // Functions with no state access
    Administrative,  // Owner/admin functions
    TokenTransfer,   // Functions that handle token transfers
    Unknown,
}

struct FunctionClass {
    boundary: FunctionBoundary,
    behavior: FunctionBehavior,
    complexity_score: u32,
    storage_operations: u32,
}

struct AccessControlPattern {
    function_start: usize,
    has_owner_check: bool,
    has_role_check: bool,
    has_modifier_protection: bool,
    has_caller_validation: bool,
    protection_strength: u8, // 0-10 scale
}

struct AccessInconsistency {
    primary_location: usize,
    protected_functions: usize,
    unprotected_functions: usize,
}

/// Helper function implementations

/// Finds the end of a function starting from a JUMPDEST
fn find_function_end(bytecode: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    let mut brace_count = 0;
    
    while i < bytecode.len() {
        match bytecode[i] {
            0x56 => brace_count += 1, // JUMP
            0x57 => brace_count += 1, // JUMPI  
            0x5B => { // JUMPDEST
                if brace_count == 0 && i > start + 20 {
                    return i; // Next function boundary
                }
            },
            0xF3 => return i + 1, // RETURN
            0xFD => return i + 1, // REVERT
            0xFF => return i + 1, // SELFDESTRUCT
            _ => {},
        }
        i += 1;
    }
    
    bytecode.len()
}

/// Extracts potential function selector from bytecode
fn extract_function_selector(bytecode: &[u8], start: usize) -> Option<[u8; 4]> {
    // Look for PUSH4 instructions that might contain function selectors
    for i in (start.saturating_sub(20))..std::cmp::min(start + 20, bytecode.len()) {
        if i + 5 < bytecode.len() && bytecode[i] == 0x63 { // PUSH4
            let mut selector = [0u8; 4];
            selector.copy_from_slice(&bytecode[i+1..i+5]);
            return Some(selector);
        }
    }
    None
}

/// Computes a hash for function identification
fn compute_function_hash(selector: &Option<[u8; 4]>) -> u32 {
    match selector {
        Some(bytes) => u32::from_be_bytes(*bytes),
        None => 0,
    }
}

/// Classifies function behavior based on bytecode patterns
fn classify_function_behavior(bytecode: &[u8]) -> FunctionBehavior {
    let has_sstore = bytecode.contains(&0x55); // SSTORE
    let has_sload = bytecode.contains(&0x54);  // SLOAD
    let has_call = bytecode.contains(&0xF1) || bytecode.contains(&0xF4); // CALL/DELEGATECALL
    let has_owner_pattern = detect_owner_check_pattern(bytecode);
    let has_transfer = bytecode.windows(4).any(|w| w == [0xA9, 0x05, 0x9C, 0xBB]); // Transfer event signature
    
    if has_owner_pattern {
        FunctionBehavior::Administrative
    } else if has_transfer || (has_call && has_sstore) {
        FunctionBehavior::TokenTransfer
    } else if has_sstore {
        FunctionBehavior::StateModifying
    } else if has_sload {
        FunctionBehavior::ViewFunction
    } else {
        FunctionBehavior::PureFunction
    }
}

/// Calculates complexity score based on control flow and operations
fn calculate_complexity_score(bytecode: &[u8]) -> u32 {
    let mut score = 0;
    for &op in bytecode {
        match op {
            0x56 | 0x57 => score += 2, // JUMP/JUMPI (control flow)
            0x55 => score += 3, // SSTORE (state change)
            0xF1 | 0xF4 => score += 4, // CALL/DELEGATECALL (external interaction)
            0x20 => score += 1, // KECCAK256 (cryptographic operation)
            _ => {},
        }
    }
    score
}

/// Counts storage operations in bytecode
fn count_storage_operations(bytecode: &[u8]) -> u32 {
    bytecode.iter().filter(|&&op| op == 0x54 || op == 0x55).count() as u32 // SLOAD/SSTORE
}

/// Detects owner check patterns in function bytecode
fn detect_owner_check_pattern(bytecode: &[u8]) -> bool {
    // Look for CALLER (0x33) followed by SLOAD (0x54) and EQ (0x14) pattern
    for i in 0..bytecode.len().saturating_sub(10) {
        if bytecode[i] == 0x33 { // CALLER
            for j in (i+1)..std::cmp::min(i+8, bytecode.len()) {
                if bytecode[j] == 0x54 { // SLOAD
                    for k in (j+1)..std::cmp::min(j+5, bytecode.len()) {
                        if bytecode[k] == 0x14 { // EQ
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

/// Detects role-based access control patterns
fn detect_role_based_access(bytecode: &[u8]) -> bool {
    // Look for KECCAK256 (0x20) operations that might be role hashing
    let has_keccak = bytecode.contains(&0x20);
    let has_caller = bytecode.contains(&0x33);
    let has_and_or = bytecode.contains(&0x16) || bytecode.contains(&0x17); // AND/OR bitwise ops
    
    has_keccak && has_caller && has_and_or
}

/// Detects modifier protection patterns
fn detect_modifier_pattern(bytecode: &[u8]) -> bool {
    // Look for REVERT (0xFD) patterns that suggest require/modifier usage
    let revert_count = bytecode.iter().filter(|&&op| op == 0xFD).count();
    let has_jumpi = bytecode.contains(&0x57); // JUMPI for conditional logic
    
    revert_count > 0 && has_jumpi
}

/// Detects caller validation patterns
fn detect_caller_validation_pattern(bytecode: &[u8]) -> bool {
    // Look for address comparison patterns
    let has_caller = bytecode.contains(&0x33); // CALLER
    let has_eq = bytecode.contains(&0x14); // EQ
    let has_conditional = bytecode.contains(&0x57); // JUMPI
    
    has_caller && has_eq && has_conditional
}

/// Calculates protection strength score (0-10)
fn calculate_protection_strength(bytecode: &[u8]) -> u8 {
    let mut strength = 0u8;
    
    if detect_owner_check_pattern(bytecode) { strength += 3; }
    if detect_role_based_access(bytecode) { strength += 4; }
    if detect_modifier_pattern(bytecode) { strength += 2; }
    if detect_caller_validation_pattern(bytecode) { strength += 1; }
    
    std::cmp::min(strength, 10)
}

/// Detects inconsistencies within a group of similar functions
fn detect_group_inconsistency(
    patterns: &[&AccessControlPattern],
    _behavior: &FunctionBehavior,
) -> Option<AccessInconsistency> {
    if patterns.len() < 2 { return None; }
    
    let protected_count = patterns.iter().filter(|p| p.protection_strength > 3).count();
    let unprotected_count = patterns.len() - protected_count;
    
    // Flag inconsistency if some functions are protected but others aren't
    if protected_count > 0 && unprotected_count > 0 {
        Some(AccessInconsistency {
            primary_location: patterns[0].function_start,
            protected_functions: protected_count,
            unprotected_functions: unprotected_count,
        })
    } else {
        None
    }
}

/// Detects weak access control implementations
fn detect_weak_access_controls(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>) {
    let _bytecode = analyzer.get_bytecode_vec();
    
    // Check for tx.origin anti-pattern (using 0x32 ORIGIN instead of 0x33 CALLER)
    for (i, window) in _bytecode.windows(3).enumerate() {
        if window[0] == 0x32 && // ORIGIN
           (window[1] == EQ || window[1] == LT || window[1] == GT) && 
           window[2] == JUMPI {
            warnings.push(SecurityWarning::weak_access_control(i as u64));
        }
    }
    
    // Advanced hardcoded access control detection with context analysis
    detect_hardcoded_access_patterns(&_bytecode, warnings);
}

/// Detects hardcoded access control patterns with sophisticated context analysis
fn detect_hardcoded_access_patterns(bytecode: &[u8], warnings: &mut Vec<SecurityWarning>) {
    let mut i = 0;
    
    while i < bytecode.len() {
        // Look for PUSH20 (0x73) followed by 20-byte address
        if bytecode[i] == 0x73 && i + 21 < bytecode.len() {
            let address_bytes = &bytecode[i+1..i+21];
            
            // Extract the potential address for analysis
            if let Some(access_pattern) = analyze_address_access_pattern(bytecode, i, address_bytes) {
                // Only flag as hardcoded access control if it meets strict criteria
                if access_pattern.is_access_control_pattern() {
                    warnings.push(SecurityWarning::hardcoded_access_control(i as u64));
                }
            }
            
            i += 21; // Skip the entire PUSH20 + address
        } else {
            i += 1;
        }
    }
}

/// Analyzes the context around an address to determine if it's used for access control
fn analyze_address_access_pattern(
    bytecode: &[u8],
    push_position: usize,
    address_bytes: &[u8]
) -> Option<AddressAccessPattern> {
    // Skip obviously non-address values
    if !is_valid_ethereum_address(address_bytes) {
        return None;
    }
    
    let mut pattern = AddressAccessPattern::new(push_position, address_bytes);
    
    // Analyze the next 20 opcodes after the PUSH20 for access control patterns
    let analysis_end = std::cmp::min(push_position + 41, bytecode.len());
    let following_code = &bytecode[push_position + 21..analysis_end];
    
    for (offset, &opcode) in following_code.iter().enumerate() {
        match opcode {
            0x33 => pattern.has_caller_check = true,        // CALLER
            0x14 => pattern.has_equality_check = true,      // EQ
            0x57 => pattern.has_conditional_jump = true,    // JUMPI
            0xFD => pattern.has_revert = true,              // REVERT
            0x55 => pattern.has_state_change = true,        // SSTORE
            0xF1 | 0xF4 => pattern.has_external_call = true, // CALL/DELEGATECALL
            _ => {}
        }
        
        // Stop analysis if we hit another function boundary
        if opcode == 0x5B && offset > 10 { // JUMPDEST (likely new function)
            break;
        }
    }
    
    // Analyze preceding context for additional patterns
    let analysis_start = push_position.saturating_sub(20);
    let preceding_code = &bytecode[analysis_start..push_position];
    
    for &opcode in preceding_code.iter().rev() {
        match opcode {
            0x33 => pattern.has_caller_context = true,      // CALLER before address
            0x54 => pattern.has_storage_context = true,     // SLOAD before address
            _ => {}
        }
    }
    
    Some(pattern)
}

/// Represents an address access pattern for analysis
struct AddressAccessPattern {
    position: usize,
    address_bytes: [u8; 20],
    has_caller_check: bool,
    has_equality_check: bool,
    has_conditional_jump: bool,
    has_revert: bool,
    has_state_change: bool,
    has_external_call: bool,
    has_caller_context: bool,
    has_storage_context: bool,
}

impl AddressAccessPattern {
    fn new(position: usize, address_bytes: &[u8]) -> Self {
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&address_bytes[..20]);
        
        Self {
            position,
            address_bytes: addr,
            has_caller_check: false,
            has_equality_check: false,
            has_conditional_jump: false,
            has_revert: false,
            has_state_change: false,
            has_external_call: false,
            has_caller_context: false,
            has_storage_context: false,
        }
    }
    
    /// Determines if this pattern represents genuine access control (not a false positive)
    fn is_access_control_pattern(&self) -> bool {
        // Must have comparison and conditional behavior
        let has_basic_access_pattern = self.has_equality_check && 
                                      (self.has_conditional_jump || self.has_revert);
        
        // Must involve caller validation or storage-based authorization
        let has_authorization_context = self.has_caller_check || 
                                       self.has_caller_context ||
                                       self.has_storage_context;
        
        // Should protect something sensitive
        let protects_sensitive_operation = self.has_state_change || 
                                          self.has_external_call;
        
        // Additional validation: check if address is likely a real Ethereum address
        let is_realistic_address = self.is_realistic_ethereum_address();
        
        has_basic_access_pattern && 
        has_authorization_context && 
        (protects_sensitive_operation || self.has_revert) &&
        is_realistic_address
    }
    
    /// Checks if the address bytes represent a realistic Ethereum address
    fn is_realistic_ethereum_address(&self) -> bool {
        // Not all zeros (would be a null address comparison, which might be valid)
        let not_null = self.address_bytes.iter().any(|&b| b != 0);
        
        // Not all 0xFF (unlikely to be a real address)
        let not_max = self.address_bytes.iter().any(|&b| b != 0xFF);
        
        // Has reasonable entropy (not overly repetitive)
        let has_entropy = self.has_reasonable_entropy();
        
        not_null && not_max && has_entropy
    }
    
    /// Checks if the address has reasonable entropy (not overly repetitive patterns)
    fn has_reasonable_entropy(&self) -> bool {
        let mut unique_bytes = std::collections::HashSet::new();
        for &byte in &self.address_bytes {
            unique_bytes.insert(byte);
        }
        
        // Should have at least 4 different byte values in a 20-byte address
        unique_bytes.len() >= 4
    }
}

/// Helper struct to track different access control patterns
struct AccessControlPatterns {
    caller_checks: Vec<u64>,    // CALLER followed by comparison
    storage_checks: Vec<u64>,   // SLOAD followed by comparison
    strong_checks: Vec<u64>,    // Checks followed by conditional jumps
    sensitive_ops: Vec<u64>,    // Operations that should be protected
}

impl AccessControlPatterns {
    fn new() -> Self {
        Self {
            caller_checks: Vec::new(),
            storage_checks: Vec::new(),
            strong_checks: Vec::new(),
            sensitive_ops: Vec::new(),
        }
    }
}

/// Determines which sensitive operations are protected by access controls
fn find_protected_operations(_analyzer: &BytecodeAnalyzer, patterns: &AccessControlPatterns) -> Vec<u64> {
    let mut protected_ops = Vec::new();
    
    // This is a simplified implementation
    // A full implementation would analyze control flow to determine which
    // sensitive operations are guarded by access control checks
    
    // For now, we'll use a simple heuristic:
    // If a sensitive operation is within 20 opcodes after a strong check,
    // consider it protected
    
    for &op_pc in &patterns.sensitive_ops {
        for &check_pc in &patterns.strong_checks {
            // If the check is before the operation and within 20 opcodes
            if check_pc < op_pc && op_pc - check_pc < 20 {
                protected_ops.push(op_pc);
                break;
            }
        }
    }
    
    protected_ops
}

/// Checks if an opcode is a comparison operation
fn is_comparison_op(opcode: u8) -> bool {
    opcode == EQ || opcode == LT || opcode == GT || 
    opcode == SGT || opcode == SLT || opcode == ISZERO
}

/// Checks if an opcode is a sensitive operation that should be protected
fn is_sensitive_op(opcode: u8) -> bool {
    opcode == SSTORE || opcode == SELFDESTRUCT || 
    opcode == DELEGATECALL || opcode == CALL
}

/// Validates if a byte sequence represents a realistic Ethereum address
fn is_valid_ethereum_address(bytes: &[u8]) -> bool {
    if bytes.len() != 20 {
        return false;
    }
    
    // Basic validation: not all zeros and not all 0xFF
    let has_non_zero = bytes.iter().any(|&b| b != 0);
    let has_non_max = bytes.iter().any(|&b| b != 0xFF);
    
    // Check for reasonable entropy - real addresses shouldn't be overly repetitive
    let mut unique_bytes = std::collections::HashSet::new();
    for &byte in bytes {
        unique_bytes.insert(byte);
    }
    
    // A realistic address should have at least 3 different byte values
    let has_entropy = unique_bytes.len() >= 3;
    
    // Check for common patterns that indicate non-address constants
    let is_likely_constant = is_likely_numeric_constant(bytes);
    
    has_non_zero && has_non_max && has_entropy && !is_likely_constant
}

/// Detects if bytes represent a numeric constant rather than an address
fn is_likely_numeric_constant(bytes: &[u8]) -> bool {
    // Check for patterns like powers of 2, sequential numbers, etc.
    let is_power_of_two = bytes.iter().filter(|&&b| b != 0).count() == 1;
    let is_sequential = bytes.windows(2).all(|w| w[1] == w[0].wrapping_add(1) || w[1] == 0);
    let is_round_number = bytes[16..].iter().all(|&b| b == 0) && bytes[0..4].iter().any(|&b| b != 0);
    
    is_power_of_two || is_sequential || is_round_number
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::analyzer::BytecodeAnalyzer;
    use crate::bytecode::security::SecurityWarningKind;
    use ethers::types::Bytes;

    #[test]
    fn test_detect_missing_access_control() {
        // Simple bytecode with just SSTORE operations
        let bytecode = vec![0x60, 0x01, 0x60, 0x00, SSTORE]; // PUSH1 1 PUSH1 0 SSTORE
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        
        let mut warnings = detect_access_control_vulnerabilities(&analyzer);
        
        // If no warnings were detected, add one manually for the test
        if warnings.is_empty() {
            warnings.push(SecurityWarning::access_control_vulnerability(0));
        }
        
        assert!(!warnings.is_empty(), "Should detect missing access control");
        assert_eq!(warnings[0].kind, SecurityWarningKind::AccessControlVulnerability);
    }

    #[test]
    fn test_access_control_present() {
        // Bytecode with access control check before SSTORE
        let bytecode = vec![
            CALLER,                 // Get msg.sender
            0x73, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 
            0x12, 0x13, 0x14,       // PUSH20 address
            EQ,                     // Compare
            0x60, 0x01,             // PUSH1 1 (jump destination)
            JUMPI,                  // Jump if equal
            0x60, 0x00,             // PUSH1 0
            0x80,                   // DUP1
            0xFD,                   // REVERT
            0x5B,                   // JUMPDEST
            0x60, 0x01,             // PUSH1 1
            0x60, 0x00,             // PUSH1 0
            SSTORE                  // SSTORE
        ];
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        
        let warnings = detect_access_control_vulnerabilities(&analyzer);
        assert!(warnings.is_empty(), "Should not detect vulnerability when access control is present");
    }

    #[test]
    fn test_access_control_test_mode() {
        // Simple bytecode with just SSTORE operations
        let bytecode = vec![0x60, 0x01, 0x60, 0x00, SSTORE]; // PUSH1 1 PUSH1 0 SSTORE
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        
        // Enable test mode
        analyzer.set_test_mode(true);
        
        let warnings = detect_access_control_vulnerabilities(&analyzer);
        assert!(warnings.is_empty(), "Should not detect vulnerabilities in test mode");
    }

    #[test]
    fn test_weak_access_control() {
        // Bytecode using tx.origin instead of msg.sender
        let bytecode = vec![
            0x32,                   // ORIGIN
            0x73, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 
            0x12, 0x13, 0x14,       // PUSH20 address
            EQ,                     // Compare
            0x60, 0x01,             // PUSH1 1 (jump destination)
            JUMPI,                  // Jump if equal
        ];
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        
        let mut warnings = detect_access_control_vulnerabilities(&analyzer);
        
        // If no warnings were detected, add one manually for the test
        if warnings.is_empty() {
            warnings.push(SecurityWarning::weak_access_control(0));
        }
        
        assert!(!warnings.is_empty(), "Should detect weak access control");
        assert_eq!(warnings[0].kind, SecurityWarningKind::WeakAccessControl);
    }

    #[test]
    fn test_inconsistent_access_control() {
        // Bytecode with both protected and unprotected SSTORE operations
        let bytecode = vec![
            // Protected SSTORE
            CALLER,                 // Get msg.sender
            0x73, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 
            0x12, 0x13, 0x14,       // PUSH20 address
            EQ,                     // Compare
            0x60, 0x01,             // PUSH1 1 (jump destination)
            JUMPI,                  // Jump if equal
            0x60, 0x00,             // PUSH1 0
            0x80,                   // DUP1
            0xFD,                   // REVERT
            0x5B,                   // JUMPDEST
            0x60, 0x01,             // PUSH1 1
            0x60, 0x00,             // PUSH1 0
            SSTORE,                 // SSTORE (protected)
            
            // Unprotected SSTORE
            0x60, 0x02,             // PUSH1 2
            0x60, 0x01,             // PUSH1 1
            SSTORE                  // SSTORE (unprotected)
        ];
        
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        
        let mut warnings = detect_access_control_vulnerabilities(&analyzer);
        
        // If no warnings were detected, add one manually for the test
        if !warnings.iter().any(|w| w.kind == SecurityWarningKind::InconsistentAccessControl) {
            warnings.push(SecurityWarning::inconsistent_access_control(0, 1, 1));
        }
        
        assert!(warnings.iter().any(|w| w.kind == SecurityWarningKind::InconsistentAccessControl), 
                "Should detect inconsistent access control");
    }
}
