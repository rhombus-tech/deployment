/// State Transition Validator
/// Validates that state transitions follow protocol rules and maintain consistency
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone)]
pub struct StateTransitionValidator {
    bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct InvalidTransition {
    pub from_state: String,
    pub to_state: String,
    pub location: usize,
    pub reason: String,
    pub severity: SecuritySeverity,
}

impl StateTransitionValidator {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn validate_all_transitions(&self) -> Vec<InvalidTransition> {
        let mut invalid = Vec::new();

        // Check for invalid state machine transitions
        invalid.extend(self.find_invalid_state_transitions());
        
        // Check for atomicity violations
        invalid.extend(self.find_atomic_transition_violations());
        
        // Check for state rollback vulnerabilities
        invalid.extend(self.find_state_rollback_issues());

        invalid
    }

    fn find_invalid_state_transitions(&self) -> Vec<InvalidTransition> {
        let mut transitions = Vec::new();

        // Look for state changes without proper validation
        if self.has_unchecked_state_change() {
            transitions.push(InvalidTransition {
                from_state: "any".to_string(),
                to_state: "invalid".to_string(),
                location: 0,
                reason: "State change without validation".to_string(),
                severity: SecuritySeverity::High,
            });
        }

        transitions
    }

    fn find_atomic_transition_violations(&self) -> Vec<InvalidTransition> {
        let mut violations = Vec::new();

        // Check for partial state updates
        if self.has_partial_state_update() {
            violations.push(InvalidTransition {
                from_state: "partial".to_string(),
                to_state: "inconsistent".to_string(),
                location: 0,
                reason: "Non-atomic state update".to_string(),
                severity: SecuritySeverity::Critical,
            });
        }

        violations
    }

    fn find_state_rollback_issues(&self) -> Vec<InvalidTransition> {
        let mut issues = Vec::new();

        // Check for state that can be incorrectly rolled back
        if self.has_rollback_vulnerability() {
            issues.push(InvalidTransition {
                from_state: "committed".to_string(),
                to_state: "rolled_back".to_string(),
                location: 0,
                reason: "State can be rolled back after commit".to_string(),
                severity: SecuritySeverity::Critical,
            });
        }

        issues
    }

    fn has_unchecked_state_change(&self) -> bool {
        // SSTORE without preceding validation
        let mut has_sstore = false;
        for (i, &byte) in self.bytecode.iter().enumerate() {
            if byte == 0x55 { // SSTORE
                // Check if there's a validation check before it
                if i > 10 && !self.has_validation_before(i) {
                    has_sstore = true;
                }
            }
        }
        has_sstore
    }

    fn has_validation_before(&self, pos: usize) -> bool {
        // Check for JUMPI (conditional) in preceding bytes
        self.bytecode.get(pos.saturating_sub(10)..pos)
            .map(|slice| slice.contains(&0x57))
            .unwrap_or(false)
    }

    fn has_partial_state_update(&self) -> bool {
        // Multiple SSTORE operations without REVERT protection
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let revert_count = self.bytecode.iter().filter(|&&b| b == 0xfd).count();
        
        sstore_count > 2 && revert_count == 0
    }

    fn has_rollback_vulnerability(&self) -> bool {
        // External calls after state changes
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check for CALL in next 20 bytes
                if self.bytecode[i..i+20].contains(&0xf1) {
                    return true;
                }
            }
        }
        false
    }
}
