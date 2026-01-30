use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// Reentrancy Lock Bypass Detector
/// 
/// Detects vulnerabilities where reentrancy guards can be bypassed through
/// various attack vectors including:
/// - Cross-function reentrancy (lock not shared)
/// - Storage collision attacks
/// - Delegatecall to bypass guard checks
/// - Read-only reentrancy (view functions)
/// 
/// **Attack Patterns**:
/// 1. Attacker finds function without guard that modifies same state
/// 2. Reentrant call to unguarded function bypasses lock
/// 3. State manipulation occurs despite primary guard
/// 4. Can also exploit view functions that read inconsistent state
/// 
/// **Detection Strategy**:
/// - Identifies inconsistent guard usage across functions
/// - Detects shared state modifications without shared guards
/// - Flags delegatecall that could bypass guards
/// - Checks for read-only reentrancy vulnerabilities
pub struct ReentrancyLockBypassDetector {
    bytecode: Vec<u8>,
}

impl ReentrancyLockBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_inconsistent_guard_usage() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::Reentrancy,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Reentrancy lock can be bypassed via cross-function reentrancy".to_string(),
                operations: Vec::new(),
                remediation: "Ensure all state-modifying functions share the same reentrancy lock".to_string(),
            });
        }

        if self.has_delegatecall_guard_bypass() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::Reentrancy,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "DELEGATECALL can bypass reentrancy guard by changing context".to_string(),
                operations: Vec::new(),
                remediation: "Avoid DELEGATECALL in functions with reentrancy guards or validate context".to_string(),
            });
        }

        if self.has_read_only_reentrancy() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::Reentrancy,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Read-only reentrancy: view function reads inconsistent state".to_string(),
                operations: Vec::new(),
                remediation: "Apply reentrancy guards to view functions or use consistent state snapshots".to_string(),
            });
        }

        if self.has_storage_collision_bypass() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::Reentrancy,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Potential storage collision allowing guard bypass".to_string(),
                operations: Vec::new(),
                remediation: "Use unique storage slots for reentrancy guards to prevent collisions".to_string(),
            });
        }

        warnings
    }

    fn has_inconsistent_guard_usage(&self) -> bool {
        let mut guarded_functions = Vec::new();
        let mut unguarded_functions_with_sstore = Vec::new();
        
        // Scan for function selectors and their guard status
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                let window = &self.bytecode[i..i+50.min(self.bytecode.len())];
                
                // Check for reentrancy guard pattern
                let has_guard = window.windows(3).any(|w| {
                    w[0] == 0x54 && w[1] == 0x15 && w[2] == 0x57 // SLOAD ISZERO JUMPI
                });
                
                // Check for state modifications (SSTORE)
                let has_sstore = window.contains(&0x55);
                
                // Check for external calls
                let has_external_call = window.iter().any(|&op| {
                    op == 0xf1 || op == 0xf4 // CALL or DELEGATECALL
                });
                
                if has_external_call && has_sstore {
                    if has_guard {
                        guarded_functions.push(selector.to_vec());
                    } else {
                        unguarded_functions_with_sstore.push(selector.to_vec());
                    }
                }
            }
        }
        
        // Vulnerability: some functions guarded, others not, both modify state
        !guarded_functions.is_empty() && !unguarded_functions_with_sstore.is_empty()
    }

    fn has_delegatecall_guard_bypass(&self) -> bool {
        // Pattern: DELEGATECALL within a guarded function
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for guard pattern
            if self.bytecode[i] == 0x54 && // SLOAD (guard check)
               i + 3 < self.bytecode.len() &&
               self.bytecode[i+1] == 0x15 && // ISZERO
               self.bytecode[i+2] == 0x57    // JUMPI
            {
                // Check if DELEGATECALL exists after guard
                let window = &self.bytecode[i+3..i+30.min(self.bytecode.len())];
                
                if window.contains(&0xf4) { // DELEGATECALL
                    // DELEGATECALL changes context, potentially bypassing guard
                    return true;
                }
            }
        }
        false
    }

    fn has_read_only_reentrancy(&self) -> bool {
        // Look for STATICCALL (view function) that reads state during external call
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xf1 { // CALL (external)
                let window = &self.bytecode[i..i+20.min(self.bytecode.len())];
                
                // Check if followed by STATICCALL (view function)
                if window.contains(&0xfa) { // STATICCALL
                    // Check if SLOAD occurs in between (reading potentially inconsistent state)
                    let call_pos = 0;
                    let staticcall_pos = window.iter().position(|&op| op == 0xfa);
                    
                    if let Some(sc_pos) = staticcall_pos {
                        let between = &window[call_pos..sc_pos];
                        if between.contains(&0x54) { // SLOAD
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn has_storage_collision_bypass(&self) -> bool {
        // Look for computed storage slots that could collide with guard slot
        let mut has_guard = false;
        let mut has_computed_slot = false;
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            // Detect standard guard pattern
            if self.bytecode[i] == 0x54 && 
               i + 2 < self.bytecode.len() &&
               self.bytecode[i+1] == 0x15 &&
               self.bytecode[i+2] == 0x57
            {
                has_guard = true;
            }
            
            // Detect computed storage slot (KECCAK256 before SLOAD/SSTORE)
            if self.bytecode[i] == 0x20 { // SHA3/KECCAK256
                let window = &self.bytecode[i..i+10.min(self.bytecode.len())];
                if window.iter().any(|&op| op == 0x54 || op == 0x55) {
                    has_computed_slot = true;
                }
            }
        }
        
        // Potential for collision if both patterns exist
        has_guard && has_computed_slot
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cross_function_reentrancy_bypass() {
        let vulnerable_bytecode = vec![
            // Function 1: guarded
            0x63, 0xaa, 0xbb, 0xcc, 0xdd, // selector
            0x54, 0x15, 0x57, // guard
            0xf1, // CALL
            0x55, // SSTORE
            // Function 2: unguarded but modifies same state
            0x63, 0x11, 0x22, 0x33, 0x44, // different selector
            0xf1, // CALL (no guard!)
            0x55, // SSTORE
        ];

        let detector = ReentrancyLockBypassDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        assert!(!warnings.is_empty(), "Should detect cross-function bypass");
    }

    #[test]
    fn test_delegatecall_bypass() {
        let vulnerable_bytecode = vec![
            0x54, 0x15, 0x57, // guard
            0xf4, // DELEGATECALL (bypasses guard context)
            0x55, // SSTORE
        ];

        let detector = ReentrancyLockBypassDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        assert!(!warnings.is_empty(), "Should detect DELEGATECALL bypass");
    }
}
