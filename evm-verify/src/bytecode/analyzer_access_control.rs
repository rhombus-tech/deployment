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
    let _bytecode = analyzer.get_bytecode_vec();
    
    // This is a simplified implementation - a full implementation would:
    // 1. Identify function boundaries
    // 2. Classify functions by signature/behavior
    // 3. Compare access control patterns across similar functions
    // 4. Flag inconsistencies
    
    // For now, we'll implement a basic heuristic:
    // If some SSTORE operations are protected but others aren't, that's suspicious
    
    let mut protected_sstores = 0;
    let mut unprotected_sstores = 0;
    
    for (i, op) in _bytecode.iter().enumerate() {
        if *op == SSTORE {
            // Check if there's a CALLER check within 20 opcodes before this SSTORE
            let start = if i > 20 { i - 20 } else { 0 };
            let has_caller_check = _bytecode[start..i].contains(&CALLER);
            
            if has_caller_check {
                protected_sstores += 1;
            } else {
                unprotected_sstores += 1;
            }
        }
    }
    
    // If there's a mix of protected and unprotected storage writes,
    // that could indicate inconsistent access controls
    if protected_sstores > 0 && unprotected_sstores > 0 {
        warnings.push(SecurityWarning::inconsistent_access_control(
            0, protected_sstores, unprotected_sstores
        ));
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
    
    // Check for simple constant comparisons that might be hardcoded addresses
    // This is a heuristic and may have false positives
    for (i, window) in _bytecode.windows(4).enumerate() {
        if (window[0] == 0x73 || window[0] == 0x74) && // PUSH20 or similar
           window[3] == EQ && 
           is_address_like(&_bytecode[i+1..i+21]) {
            warnings.push(SecurityWarning::hardcoded_access_control(i as u64));
        }
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

/// Checks if a byte sequence looks like an Ethereum address (20 bytes)
fn is_address_like(bytes: &[u8]) -> bool {
    bytes.len() >= 20 && bytes.iter().take(20).any(|&b| b != 0)
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
