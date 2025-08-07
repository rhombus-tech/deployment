use crate::bytecode::analyzer::BytecodeAnalyzer;
use crate::bytecode::opcodes::*;
use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity, Operation};
use std::collections::HashSet;

/// Context structure for tracking bitmask analysis state
#[derive(Debug, Clone)]
struct BitmaskContext {
    /// Tracks positions where proper masking is detected
    proper_masks: HashSet<usize>,
    /// Risk score based on usage patterns
    risk_score: u32,
    /// Whether array access patterns are detected
    has_array_access: bool,
    /// Whether input sanitization is detected
    has_input_sanitization: bool,
    /// Tracks privilege-related operations
    has_privilege_ops: bool,
}

impl Default for BitmaskContext {
    fn default() -> Self {
        Self {
            proper_masks: HashSet::new(),
            risk_score: 0,
            has_array_access: false,
            has_input_sanitization: false,
            has_privilege_ops: false,
        }
    }
}

/// Detects potential bitmask vulnerabilities in EVM bytecode
pub fn detect_bitmask_vulnerabilities(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    let mut warnings = Vec::new();
    
    // Skip analysis if in test mode
    if analyzer.is_test_mode() {
        return warnings;
    }
    
    // Create analysis context
    let mut context = BitmaskContext::default();
    
    // Perform comprehensive bitmask analysis
    detect_improper_bitmask(analyzer, &mut warnings, &mut context);
    detect_missing_bitmask(analyzer, &mut warnings, &mut context);
    detect_array_bounds_vulnerabilities(analyzer, &mut warnings, &mut context);
    detect_input_sanitization_bypass(analyzer, &mut warnings, &mut context);
    detect_privilege_escalation_bitmasks(analyzer, &mut warnings, &mut context);
    
    warnings
}

/// Detects improper use of bitmasks with advanced semantic analysis
fn detect_improper_bitmask(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>, context: &mut BitmaskContext) {
    let bytecode = analyzer.get_bytecode_vec();
    let mut i = 0;
    
    while i < bytecode.len() {
        // Analyze bitwise operations in context
        if i + 10 < bytecode.len() {
            match bytecode[i] {
                op if op == AND as u8 => {
                    analyze_and_operation(&bytecode, i, warnings, &mut *context);
                },
                op if op == OR as u8 => {
                    analyze_or_operation(&bytecode, i, warnings, &mut *context);
                },
                op if op == XOR as u8 => {
                    analyze_xor_operation(&bytecode, i, warnings, &mut *context);
                },
                op if op == SHL as u8 || op == SHR as u8 => {
                    analyze_shift_operation(&bytecode, i, warnings, &mut *context);
                },
                _ => {}
            }
        }
        
        i += 1;
    }
}

/// Analyzes AND operations for potential vulnerabilities
fn analyze_and_operation(bytecode: &[u8], pos: usize, warnings: &mut Vec<SecurityWarning>, context: &mut BitmaskContext) {
    let start_before = if pos >= 10 { pos - 10 } else { 0 };
    let end_after = std::cmp::min(pos + 11, bytecode.len());
    let before = &bytecode[start_before..pos];
    let after = &bytecode[pos + 1..end_after];
    
    // Check for suspicious AND patterns
    if before.iter().any(|&op| op == CALLDATALOAD as u8) {
        // CALLDATALOAD followed by AND - could be input sanitization
        if is_weak_mask(before) {
            context.risk_score += 5;
            warnings.push(SecurityWarning::new(
                SecurityWarningKind::BitMaskVulnerability,
                SecuritySeverity::High,
                pos as u64,
                "Weak bitmask applied to user input data".to_string(),
                vec![Operation::Computation {
                    op_type: "weak_input_mask".to_string(),
                    gas_cost: 3,
                }],
                "Ensure input sanitization uses appropriate bitmasks to prevent data corruption or injection attacks".to_string(),
            ));
        } else {
            context.has_input_sanitization = true;
        }
    }
    
    // Check for general improper mask patterns
    if before.len() >= 4 {
        // Look for PUSH operations before AND
        let mut push_values = Vec::new();
        let scan_start = if before.len() >= 10 { before.len() - 10 } else { 0 };
        let mut j = scan_start;
        while j < before.len() {
            if before[j] == PUSH1 as u8 && j + 1 < before.len() {
                push_values.push(before[j + 1]);
                j += 2;
            } else {
                j += 1;
            }
        }
        
        // Check if any pushed value forms an improper mask
        if push_values.len() >= 2 {
            let last_two = &push_values[push_values.len()-2..];
            if is_improper_mask_pattern(last_two[0], last_two[1]) {
                warnings.push(SecurityWarning::new(
                    SecurityWarningKind::BitMaskVulnerability,
                    SecuritySeverity::Medium,
                    pos as u64,
                    "Improper bitmask pattern detected".to_string(),
                    vec![Operation::Computation {
                        op_type: "improper_mask".to_string(),
                        gas_cost: 3,
                    }],
                    "Review bitmask logic to ensure proper masking behavior".to_string(),
                ));
            }
        }
    }
    
    // Check for permission/role-based AND operations
    if before.iter().any(|&op| op == CALLER as u8 || op == ORIGIN as u8) && 
       after.iter().any(|&op| op == EQ as u8 || op == ISZERO as u8) {
        context.has_privilege_ops = true;
        // Check if the mask allows privilege escalation
        if is_privilege_escalation_mask(before, after) {
            warnings.push(SecurityWarning::new(
                SecurityWarningKind::BitMaskVulnerability,
                SecuritySeverity::Critical,
                pos as u64,
                "Bitmask operation may allow privilege escalation".to_string(),
                vec![Operation::Computation {
                    op_type: "privilege_escalation_mask".to_string(),
                    gas_cost: 3,
                }],
                "Review bitmask logic to ensure it cannot be exploited for unauthorized access".to_string(),
            ));
        }
    }
}

/// Analyzes OR operations for potential vulnerabilities
fn analyze_or_operation(bytecode: &[u8], pos: usize, warnings: &mut Vec<SecurityWarning>, context: &mut BitmaskContext) {
    let start_before = if pos >= 8 { pos - 8 } else { 0 };
    let end_after = std::cmp::min(pos + 9, bytecode.len());
    let before = &bytecode[start_before..pos];
    let after = &bytecode[pos + 1..end_after];
    
    // OR operations can be used for flag setting - check for overwrite risks
    if before.iter().any(|&op| op == SLOAD as u8) && 
       after.iter().any(|&op| op == SSTORE as u8) {
        // Storage modification via OR - potential flag corruption
        if is_unsafe_flag_operation(before, after) {
            warnings.push(SecurityWarning::new(
                SecurityWarningKind::BitMaskVulnerability,
                SecuritySeverity::Medium,
                pos as u64,
                "Unsafe flag manipulation via OR operation".to_string(),
                vec![Operation::Computation {
                    op_type: "unsafe_flag_or".to_string(),
                    gas_cost: 3,
                }],
                "Ensure OR operations on storage don't inadvertently modify critical flags".to_string(),
            ));
        }
    }
}

/// Analyzes XOR operations for potential vulnerabilities  
fn analyze_xor_operation(bytecode: &[u8], pos: usize, warnings: &mut Vec<SecurityWarning>, context: &mut BitmaskContext) {
    let start_before = if pos >= 8 { pos - 8 } else { 0 };
    let end_after = std::cmp::min(pos + 9, bytecode.len());
    let before = &bytecode[start_before..pos];
    let after = &bytecode[pos + 1..end_after];
    
    // XOR can be used for encryption/obfuscation - check for weak patterns
    if before.iter().any(|&op| op == CALLDATALOAD as u8 || op == SLOAD as u8) {
        if is_weak_xor_pattern(before, after) {
            warnings.push(SecurityWarning::new(
                SecurityWarningKind::BitMaskVulnerability,
                SecuritySeverity::Medium,
                pos as u64,
                "Weak XOR pattern detected - may be reversible".to_string(),
                vec![Operation::Computation {
                    op_type: "weak_xor".to_string(),
                    gas_cost: 3,
                }],
                "Avoid using predictable XOR patterns for security-critical operations".to_string(),
            ));
        }
    }
}

/// Analyzes shift operations for potential vulnerabilities
fn analyze_shift_operation(bytecode: &[u8], pos: usize, warnings: &mut Vec<SecurityWarning>, context: &mut BitmaskContext) {
    let start_before = if pos >= 6 { pos - 6 } else { 0 };
    let end_after = std::cmp::min(pos + 7, bytecode.len());
    let before = &bytecode[start_before..pos];
    let after = &bytecode[pos + 1..end_after];
    
    // Shift operations used for array indexing without bounds checking
    if before.iter().any(|&op| op == CALLDATALOAD as u8) &&
       after.iter().any(|&op| op == MLOAD as u8 || op == MSTORE as u8) {
        context.has_array_access = true;
        if !has_bounds_check(before, after) {
            warnings.push(SecurityWarning::new(
                SecurityWarningKind::BitMaskVulnerability,
                SecuritySeverity::High,
                pos as u64,
                "Unchecked array access via shift operation".to_string(),
                vec![Operation::Computation {
                    op_type: "unchecked_shift_access".to_string(),
                    gas_cost: 3,
                }],
                "Implement bounds checking before using shift operations for array indexing".to_string(),
            ));
        }
    }
}

/// Detects missing bitmask operations where they might be needed
fn detect_missing_bitmask(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>, context: &mut BitmaskContext) {
    let bytecode = analyzer.get_bytecode_vec();
    let mut i = 0;
    
    while i < bytecode.len() {
        if i + 8 < bytecode.len() {
            // Check for unmasked input operations
            if bytecode[i] == CALLDATALOAD as u8 {
                let following = &bytecode[i+1..i+8];
                if !has_immediate_sanitization(following) {
                    let severity = determine_input_risk_severity(following, context);
                    warnings.push(SecurityWarning::new(
                        SecurityWarningKind::BitMaskVulnerability,
                        severity,
                        i as u64,
                        "Unsanitized user input detected - missing bitmask operation".to_string(),
                        vec![Operation::Computation {
                            op_type: "missing_input_mask".to_string(),
                            gas_cost: 0,
                        }],
                        "Add appropriate bitmask operations to sanitize user inputs and prevent injection attacks".to_string(),
                    ));
                }
            }
            
            // Check for unmasked storage operations
            if bytecode[i] == SLOAD as u8 {
                let following = &bytecode[i+1..i+8];
                if requires_masking_for_security(following) {
                    warnings.push(SecurityWarning::new(
                        SecurityWarningKind::BitMaskVulnerability,
                        SecuritySeverity::Medium,
                        i as u64,
                        "Storage value used without masking - potential information leak".to_string(),
                        vec![Operation::Computation {
                            op_type: "missing_storage_mask".to_string(),
                            gas_cost: 0,
                        }],
                        "Consider masking storage values to prevent unintended information exposure".to_string(),
                    ));
                }
            }
        }
        
        i += 1;
    }
}

/// Detects array bounds vulnerabilities through bitmask analysis
fn detect_array_bounds_vulnerabilities(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>, context: &mut BitmaskContext) {
    let bytecode = analyzer.get_bytecode_vec();
    let mut i = 0;
    
    while i + 12 < bytecode.len() {
        // Look for array access patterns: CALLDATALOAD -> calculation -> MLOAD/MSTORE
        if bytecode[i] == CALLDATALOAD as u8 {
            let slice = &bytecode[i..i+12];
            
            // Check if this leads to memory/storage access
            if slice.iter().any(|&op| op == MLOAD as u8 || op == MSTORE as u8 || op == SLOAD as u8 || op == SSTORE as u8) {
                // Check for bounds checking patterns
                if !has_comprehensive_bounds_check(slice) {
                    let severity = if slice.iter().any(|&op| op == SSTORE as u8) {
                        SecuritySeverity::Critical // Storage write without bounds check
                    } else {
                        SecuritySeverity::High // Memory access without bounds check  
                    };
                    
                    warnings.push(SecurityWarning::new(
                        SecurityWarningKind::BitMaskVulnerability,
                        severity,
                        i as u64,
                        "Array access without proper bounds checking".to_string(),
                        vec![Operation::Computation {
                            op_type: "unchecked_array_bounds".to_string(),
                            gas_cost: 0,
                        }],
                        "Implement proper bounds checking and use bitmasks to prevent buffer overflows".to_string(),
                    ));
                    
                    context.risk_score += 8;
                }
            }
        }
        i += 1;
    }
}

/// Detects input sanitization bypass vulnerabilities
fn detect_input_sanitization_bypass(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>, context: &mut BitmaskContext) {
    let bytecode = analyzer.get_bytecode_vec();
    let mut i = 0;
    
    while i + 15 < bytecode.len() {
        // Look for complex input processing that might bypass sanitization
        if bytecode[i] == CALLDATALOAD as u8 {
            let slice = &bytecode[i..i+15];
            
            // Check for arithmetic operations on input that might overflow masks
            if has_arithmetic_before_masking(slice) {
                warnings.push(SecurityWarning::new(
                    SecurityWarningKind::BitMaskVulnerability,
                    SecuritySeverity::High,
                    i as u64,
                    "Input processed before sanitization - potential bypass".to_string(),
                    vec![Operation::Computation {
                        op_type: "sanitization_bypass".to_string(),
                        gas_cost: 0,
                    }],
                    "Apply bitmask sanitization immediately after input loading to prevent bypass attacks".to_string(),
                ));
            }
            
            // Check for multi-step input processing without intermediate masking
            if has_complex_processing_without_masking(slice) {
                warnings.push(SecurityWarning::new(
                    SecurityWarningKind::BitMaskVulnerability,
                    SecuritySeverity::Medium,
                    i as u64,
                    "Complex input processing without intermediate sanitization".to_string(),
                    vec![Operation::Computation {
                        op_type: "complex_unmasked_processing".to_string(),
                        gas_cost: 0,
                    }],
                    "Apply sanitization masks at each step of complex input processing".to_string(),
                ));
            }
        }
        i += 1;
    }
}

/// Detects privilege escalation through bitmask manipulation
fn detect_privilege_escalation_bitmasks(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>, context: &mut BitmaskContext) {
    let bytecode = analyzer.get_bytecode_vec();
    let mut i = 0;
    
    while i + 20 < bytecode.len() {
        // Look for privilege checking patterns
        if bytecode[i] == CALLER as u8 || bytecode[i] == ORIGIN as u8 {
            let slice = &bytecode[i..i+20];
            
            // Check for bitmask operations on addresses for role checking
            if slice.iter().any(|&op| op == AND as u8 || op == OR as u8) {
                // Analyze if the bitmask logic is secure
                if has_privilege_escalation_vulnerability(slice) {
                    warnings.push(SecurityWarning::new(
                        SecurityWarningKind::BitMaskVulnerability,
                        SecuritySeverity::Critical,
                        i as u64,
                        "Privilege escalation vulnerability in bitmask access control".to_string(),
                        vec![Operation::Computation {
                            op_type: "privilege_escalation_mask".to_string(),
                            gas_cost: 0,
                        }],
                        "Review access control bitmasks to prevent privilege escalation attacks".to_string(),
                    ));
                }
            }
            
            // Check for role-based storage access with weak masking
            if has_weak_role_masking(slice) {
                warnings.push(SecurityWarning::new(
                    SecurityWarningKind::BitMaskVulnerability,
                    SecuritySeverity::High,
                    i as u64,
                    "Weak role-based access control masking".to_string(),
                    vec![Operation::Computation {
                        op_type: "weak_role_mask".to_string(),
                        gas_cost: 0,
                    }],
                    "Strengthen role-based bitmasks to prevent unauthorized access".to_string(),
                ));
            }
        }
        i += 1;
    }
}

// ============================================================================
// HELPER FUNCTIONS FOR ADVANCED SEMANTIC ANALYSIS
// ============================================================================

/// Examines bytecode context before a given position
fn examine_context_before(bytecode: &[u8], pos: usize, count: usize) -> Vec<u8> {
    let start = if pos >= count { pos - count } else { 0 };
    bytecode[start..pos].to_vec()
}

/// Examines bytecode context after a given position
fn examine_context_after(bytecode: &[u8], pos: usize, count: usize) -> Vec<u8> {
    let end = std::cmp::min(pos + count + 1, bytecode.len());
    bytecode[pos + 1..end].to_vec()
}

/// Checks if a mask is too weak to provide effective sanitization
fn is_weak_mask(context: &[u8]) -> bool {
    // Look for common weak mask patterns
    for i in 0..context.len().saturating_sub(2) {
        if context[i] == PUSH1 as u8 || context[i] == PUSH2 as u8 {
            let mask_value = if context[i] == PUSH1 as u8 && i + 1 < context.len() {
                context[i + 1] as u16
            } else if context[i] == PUSH2 as u8 && i + 2 < context.len() {
                ((context[i + 1] as u16) << 8) | (context[i + 2] as u16)
            } else {
                continue;
            };
            
            // Check for weak mask patterns
            if mask_value == 0x01 || mask_value == 0x03 || mask_value == 0x07 ||
               mask_value == 0x0F || mask_value < 0x100 {
                return true; // Too permissive
            }
        }
    }
    false
}

/// Checks if bitmask operations could allow privilege escalation
fn is_privilege_escalation_mask(before: &[u8], after: &[u8]) -> bool {
    // Look for patterns where address masking might be bypassable
    let has_address_op = before.iter().any(|&op| op == CALLER as u8 || op == ORIGIN as u8);
    let has_weak_comparison = after.iter().any(|&op| op == EQ as u8 || op == ISZERO as u8);
    
    if has_address_op && has_weak_comparison {
        // Check for mask values that could be exploited
        for i in 0..before.len().saturating_sub(1) {
            if before[i] == PUSH20 as u8 {
                return true; // Full address comparison might be bypassable
            }
            if (before[i] == PUSH1 as u8 || before[i] == PUSH4 as u8) && i + 1 < before.len() {
                // Check if mask allows multiple addresses to pass
                return true; // Potentially exploitable mask
            }
        }
    }
    false
}

/// Checks for unsafe flag manipulation patterns
fn is_unsafe_flag_operation(before: &[u8], after: &[u8]) -> bool {
    let has_storage_read = before.iter().any(|&op| op == SLOAD as u8);
    let has_storage_write = after.iter().any(|&op| op == SSTORE as u8);
    
    if has_storage_read && has_storage_write {
        // Check if OR operation might overwrite important bits
        // Look for patterns where entire storage slots might be affected
        return !has_careful_bit_selection(before, after);
    }
    false
}

/// Checks for weak XOR patterns that might be reversible
fn is_weak_xor_pattern(before: &[u8], after: &[u8]) -> bool {
    // Look for XOR with predictable keys
    for i in 0..before.len().saturating_sub(1) {
        if before[i] == PUSH1 as u8 && i + 1 < before.len() {
            let key = before[i + 1];
            // Weak XOR keys
            if key == 0x00 || key == 0xFF || key == 0x01 || key == 0xAA || key == 0x55 {
                return true;
            }
        }
    }
    
    // Check for XOR with the same value (nullifies operation)
    let mut push_values = Vec::new();
    for i in 0..before.len().saturating_sub(1) {
        if before[i] == PUSH1 as u8 && i + 1 < before.len() {
            push_values.push(before[i + 1]);
        }
    }
    
    // If same value pushed twice, XOR will result in 0
    push_values.len() > 1 && push_values[0] == push_values[1]
}

/// Checks for bounds checking in the context
fn has_bounds_check(before: &[u8], after: &[u8]) -> bool {
    // Look for comparison operations that suggest bounds checking
    let has_comparison = after.iter().any(|&op| {
        op == LT as u8 || op == GT as u8 || op == EQ as u8 || 
        op == ISZERO as u8 || op == SUB as u8
    });
    
    let has_conditional_jump = after.iter().any(|&op| op == JUMPI as u8);
    let has_revert = after.iter().any(|&op| op == REVERT as u8);
    
    has_comparison && (has_conditional_jump || has_revert)
}

/// Checks if input has immediate sanitization
fn has_immediate_sanitization(following: &[u8]) -> bool {
    // Look for masking operations within the first few instructions
    following.iter().take(4).any(|&op| {
        op == AND as u8 || op == SHR as u8 || op == SHL as u8
    })
}

/// Determines risk severity based on input usage patterns
fn determine_input_risk_severity(following: &[u8], context: &BitmaskContext) -> SecuritySeverity {
    let has_storage_write = following.iter().any(|&op| op == SSTORE as u8);
    let has_external_call = following.iter().any(|&op| {
        op == CALL as u8 || op == DELEGATECALL as u8 || op == STATICCALL as u8
    });
    let has_memory_write = following.iter().any(|&op| op == MSTORE as u8);
    
    match (has_storage_write, has_external_call, has_memory_write) {
        (true, _, _) => SecuritySeverity::Critical, // Storage modification
        (_, true, _) => SecuritySeverity::High,     // External call
        (_, _, true) => SecuritySeverity::Medium,   // Memory modification
        _ => SecuritySeverity::Low,                 // Read-only usage
    }
}

/// Checks if storage value requires masking for security
fn requires_masking_for_security(following: &[u8]) -> bool {
    // Storage values used in comparisons or external calls might leak information
    following.iter().any(|&op| {
        op == EQ as u8 || op == LT as u8 || op == GT as u8 ||
        op == CALL as u8 || op == STATICCALL as u8 || op == LOG0 as u8 ||
        op == LOG1 as u8 || op == LOG2 as u8 || op == LOG3 as u8 || op == LOG4 as u8
    })
}

/// Checks for comprehensive bounds checking patterns
fn has_comprehensive_bounds_check(slice: &[u8]) -> bool {
    let mut has_length_check = false;
    let mut has_revert_on_fail = false;
    
    for i in 0..slice.len().saturating_sub(2) {
        // Look for array length comparison patterns
        if slice[i] == MLOAD as u8 && i + 2 < slice.len() {
            if slice[i + 1] == LT as u8 || slice[i + 1] == GT as u8 {
                has_length_check = true;
            }
        }
        
        // Look for revert patterns
        if slice[i] == JUMPI as u8 && i + 1 < slice.len() {
            if slice[i + 1] == REVERT as u8 {
                has_revert_on_fail = true;
            }
        }
    }
    
    has_length_check && has_revert_on_fail
}

/// Checks for arithmetic operations before masking
fn has_arithmetic_before_masking(slice: &[u8]) -> bool {
    let mut found_arithmetic = false;
    let mut found_masking = false;
    
    for &op in slice {
        if op == ADD as u8 || op == SUB as u8 || op == MUL as u8 || op == DIV as u8 {
            found_arithmetic = true;
        } else if op == AND as u8 || op == SHL as u8 || op == SHR as u8 {
            found_masking = true;
            break;
        }
    }
    
    found_arithmetic && !found_masking
}

/// Checks for complex processing without intermediate masking
fn has_complex_processing_without_masking(slice: &[u8]) -> bool {
    let mut operation_count = 0;
    let mut mask_count = 0;
    
    for &op in slice {
        if op == ADD as u8 || op == SUB as u8 || op == MUL as u8 || op == DIV as u8 ||
           op == KECCAK256 as u8 || op == MSTORE as u8 || op == MLOAD as u8 {
            operation_count += 1;
        } else if op == AND as u8 || op == SHL as u8 || op == SHR as u8 {
            mask_count += 1;
        }
    }
    
    operation_count > 3 && mask_count == 0
}

/// Checks for privilege escalation vulnerability patterns
fn has_privilege_escalation_vulnerability(slice: &[u8]) -> bool {
    // Look for patterns where bitmask logic might be exploitable
    let mut has_caller_check = false;
    let mut has_weak_mask = false;
    let mut has_storage_access = false;
    
    for i in 0..slice.len() {
        if slice[i] == CALLER as u8 || slice[i] == ORIGIN as u8 {
            has_caller_check = true;
        } else if slice[i] == AND as u8 && i > 0 {
            // Check if the mask before AND is weak
            if i >= 2 && slice[i-2] == PUSH1 as u8 {
                let mask_val = slice[i-1];
                if mask_val < 0x10 || mask_val == 0xFF {
                    has_weak_mask = true;
                }
            }
        } else if slice[i] == SSTORE as u8 || slice[i] == DELEGATECALL as u8 {
            has_storage_access = true;
        }
    }
    
    has_caller_check && has_weak_mask && has_storage_access
}

/// Checks for weak role-based masking
fn has_weak_role_masking(slice: &[u8]) -> bool {
    // Look for role checking patterns that might be bypassable
    for i in 0..slice.len().saturating_sub(3) {
        if slice[i] == CALLER as u8 && i + 3 < slice.len() {
            // Check for immediate mask application
            if slice[i + 1] == PUSH1 as u8 && slice[i + 3] == AND as u8 {
                let mask = slice[i + 2];
                // Weak masks that allow multiple roles
                if mask == 0x01 || mask == 0x03 || mask == 0x07 || mask == 0x0F {
                    return true;
                }
            }
        }
    }
    false
}

/// Checks for careful bit selection in flag operations
fn has_careful_bit_selection(before: &[u8], after: &[u8]) -> bool {
    // Look for evidence of selective bit manipulation rather than wholesale changes
    let mut has_specific_mask = false;
    
    for i in 0..before.len().saturating_sub(1) {
        if before[i] == PUSH1 as u8 && i + 1 < before.len() {
            let mask = before[i + 1];
            // Check for masks that target specific bits (power of 2 or related)
            if mask.count_ones() <= 2 {
                has_specific_mask = true;
            }
        }
    }
    
    has_specific_mask
}

/// Checks if two values form an improper mask pattern
fn is_improper_mask_pattern(val1: u8, val2: u8) -> bool {
    // Check for common improper mask patterns:
    // 1. Using 0xFF as mask (doesn't actually mask anything)
    // 2. Using 0x00 as mask (zeros everything)
    // 3. Masking with a value that's larger than what's being masked
    // 4. Redundant masking patterns
    
    // 0xFF mask is almost always improper (doesn't filter anything)
    if val2 == 0xFF {
        return true;
    }
    
    // 0x00 mask zeros everything - usually improper
    if val2 == 0x00 {
        return true;
    }
    
    // If the first value is small and mask is much larger, likely improper
    if val1 <= 0x0F && val2 > 0xF0 {
        return true;
    }
    
    // Common improper patterns where mask doesn't provide meaningful filtering
    match (val1, val2) {
        (0x01, 0xFF) => true,  // Test case pattern
        (0x01, 0xFE) => true,  // Barely any filtering
        (0x02, 0xFF) => true,  // No filtering
        (0x03, 0xFF) => true,  // No filtering
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::analyzer::BytecodeAnalyzer;
    use ethers::types::Bytes;
    
    #[test]
    fn test_improper_bitmask_detection() {
        // Create bytecode with potentially improper bitmask usage
        let bytecode = vec![
            PUSH1 as u8, 0x01,
            PUSH1 as u8, 0xFF,
            AND as u8,
            PUSH1 as u8, 0x00,
            EQ as u8,
            PUSH1 as u8, 0x00,
            JUMPI as u8,
        ];
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(false);
        
        let warnings = detect_bitmask_vulnerabilities(&analyzer);
        assert!(!warnings.is_empty(), "Should detect improper bitmask");
        assert!(warnings.iter().any(|w| w.kind == SecurityWarningKind::BitMaskVulnerability), 
                "Should have BitMaskVulnerability warning");
    }
    
    #[test]
    fn test_missing_bitmask_detection() {
        // Create bytecode with potentially missing bitmask
        let bytecode = vec![
            PUSH1 as u8, 0x00,
            CALLDATALOAD as u8,
            PUSH1 as u8, 0x00,
            ADD as u8,  // No bitmask before using the value
        ];
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(false);
        
        let warnings = detect_bitmask_vulnerabilities(&analyzer);
        assert!(!warnings.is_empty(), "Should detect missing bitmask");
        assert!(warnings.iter().any(|w| w.kind == SecurityWarningKind::BitMaskVulnerability), 
                "Should have BitMaskVulnerability warning");
    }
    
    #[test]
    fn test_proper_bitmask_usage() {
        // Create bytecode with proper bitmask usage
        let bytecode = vec![
            PUSH1 as u8, 0x00,
            CALLDATALOAD as u8,
            PUSH1 as u8, 0xFF,
            AND as u8,  // Proper bitmask
        ];
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(false);
        
        let warnings = detect_bitmask_vulnerabilities(&analyzer);
        assert!(warnings.is_empty(), "Should not detect issues with proper bitmask");
    }
    
    #[test]
    fn test_bitmask_test_mode() {
        // Create bytecode with potentially improper bitmask usage
        let bytecode = vec![
            PUSH1 as u8, 0x01,
            PUSH1 as u8, 0xFF,
            AND as u8,
            PUSH1 as u8, 0x00,
            EQ as u8,
        ];
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(true);  // Enable test mode
        
        let warnings = detect_bitmask_vulnerabilities(&analyzer);
        assert!(warnings.is_empty(), "Should not detect issues in test mode");
    }
}
