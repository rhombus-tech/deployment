/// Composition Safety Validator
/// Validates that contract compositions are safe and free from interaction vulnerabilities
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone)]
pub struct CompositionSafetyValidator {
    bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CompositionHazard {
    pub hazard_type: String,
    pub contracts_involved: Vec<String>,
    pub interaction_pattern: String,
    pub severity: SecuritySeverity,
}

impl CompositionSafetyValidator {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn validate_composition_safety(&self) -> Vec<CompositionHazard> {
        let mut hazards = Vec::new();

        // Check for unsafe callback chains
        hazards.extend(self.detect_unsafe_callback_chains());
        
        // Check for circular dependencies
        hazards.extend(self.detect_circular_dependencies());
        
        // Check for state synchronization issues
        hazards.extend(self.detect_state_sync_issues());
        
        // Check for atomic composition violations
        hazards.extend(self.detect_atomicity_violations());

        hazards
    }

    fn detect_unsafe_callback_chains(&self) -> Vec<CompositionHazard> {
        let mut chains = Vec::new();

        // Callback patterns that can lead to reentrancy or unexpected state
        if self.has_unsafe_callback_chain() {
            chains.push(CompositionHazard {
                hazard_type: "Unsafe Callback Chain".to_string(),
                contracts_involved: vec!["A".to_string(), "B".to_string(), "C".to_string()],
                interaction_pattern: "A calls B, B calls C, C calls A".to_string(),
                severity: SecuritySeverity::Critical,
            });
        }

        chains
    }

    fn detect_circular_dependencies(&self) -> Vec<CompositionHazard> {
        let mut circular = Vec::new();

        // Circular call patterns
        if self.has_circular_dependency() {
            circular.push(CompositionHazard {
                hazard_type: "Circular Dependency".to_string(),
                contracts_involved: vec!["A".to_string(), "B".to_string()],
                interaction_pattern: "A depends on B, B depends on A".to_string(),
                severity: SecuritySeverity::High,
            });
        }

        circular
    }

    fn detect_state_sync_issues(&self) -> Vec<CompositionHazard> {
        let mut issues = Vec::new();

        // State synchronization problems across contracts
        if self.has_state_sync_issue() {
            issues.push(CompositionHazard {
                hazard_type: "State Synchronization Issue".to_string(),
                contracts_involved: vec!["A".to_string(), "B".to_string()],
                interaction_pattern: "Shared state not properly synchronized".to_string(),
                severity: SecuritySeverity::High,
            });
        }

        issues
    }

    fn detect_atomicity_violations(&self) -> Vec<CompositionHazard> {
        let mut violations = Vec::new();

        // Multi-contract operations that should be atomic but aren't
        if self.has_atomicity_violation() {
            violations.push(CompositionHazard {
                hazard_type: "Non-Atomic Composition".to_string(),
                contracts_involved: vec!["A".to_string(), "B".to_string()],
                interaction_pattern: "Multi-step operation not protected from partial execution".to_string(),
                severity: SecuritySeverity::Critical,
            });
        }

        violations
    }

    fn has_unsafe_callback_chain(&self) -> bool {
        // Multiple external calls that could form a cycle
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xf1 || b == 0xf4).count();
        call_count >= 3
    }

    fn has_circular_dependency(&self) -> bool {
        // External calls followed by more external calls (potential cycle)
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0xf1 { // First CALL
                // Look for another CALL within 50 bytes
                if self.bytecode[i+1..i+50].contains(&0xf1) {
                    return true;
                }
            }
        }
        false
    }

    fn has_state_sync_issue(&self) -> bool {
        // SSTORE followed by external call without proper locking
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check for CALL in next 20 bytes without lock check
                if self.bytecode[i..i+20].contains(&0xf1) && !self.has_lock_at(i) {
                    return true;
                }
            }
        }
        false
    }

    fn has_atomicity_violation(&self) -> bool {
        // Multiple state changes with external calls in between
        let mut state_changes = 0;
        let mut has_external_call = false;
        
        for &byte in self.bytecode.iter() {
            if byte == 0x55 { // SSTORE
                state_changes += 1;
            }
            if byte == 0xf1 || byte == 0xf4 { // CALL or DELEGATECALL
                has_external_call = true;
            }
        }
        
        state_changes > 1 && has_external_call
    }

    fn has_lock_at(&self, pos: usize) -> bool {
        // Check for reentrancy lock pattern before position
        if pos < 10 {
            return false;
        }
        
        // Look for SLOAD + check pattern (reentrancy guard)
        self.bytecode[pos.saturating_sub(10)..pos]
            .windows(2)
            .any(|w| w == &[0x54, 0x15]) // SLOAD + ISZERO
    }

    pub fn calculate_composition_risk(&self) -> f64 {
        let hazards = self.validate_composition_safety();
        let critical = hazards.iter().filter(|h| matches!(h.severity, SecuritySeverity::Critical)).count();
        let high = hazards.iter().filter(|h| matches!(h.severity, SecuritySeverity::High)).count();
        
        (critical as f64 * 1.0) + (high as f64 * 0.6)
    }
}
