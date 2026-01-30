/// Access Control Evolution Validator
/// Validates that access control changes over time are safe and intentional
use crate::bytecode::SecuritySeverity;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct AccessControlEvolutionValidator {
    bytecode: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlIssue {
    pub issue_type: String,
    pub location: usize,
    pub description: String,
    pub severity: SecuritySeverity,
}

impl AccessControlEvolutionValidator {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn validate_access_control_evolution(&self) -> Vec<AccessControlIssue> {
        let mut issues = Vec::new();

        // Check for privilege escalation paths
        issues.extend(self.check_privilege_escalation());
        
        // Check for role transition vulnerabilities
        issues.extend(self.check_role_transitions());
        
        // Check for ownership transfer issues
        issues.extend(self.check_ownership_transfers());
        
        // Check for timelock bypasses
        issues.extend(self.check_timelock_evolution());

        issues
    }

    fn check_privilege_escalation(&self) -> Vec<AccessControlIssue> {
        let mut escalations = Vec::new();

        if self.has_privilege_escalation_path() {
            escalations.push(AccessControlIssue {
                issue_type: "Privilege Escalation".to_string(),
                location: 0,
                description: "User can escalate their privileges over time".to_string(),
                severity: SecuritySeverity::Critical,
            });
        }

        escalations
    }

    fn check_role_transitions(&self) -> Vec<AccessControlIssue> {
        let mut transitions = Vec::new();

        if self.has_unsafe_role_transition() {
            transitions.push(AccessControlIssue {
                issue_type: "Unsafe Role Transition".to_string(),
                location: 0,
                description: "Role changes without proper validation".to_string(),
                severity: SecuritySeverity::High,
            });
        }

        transitions
    }

    fn check_ownership_transfers(&self) -> Vec<AccessControlIssue> {
        let mut transfers = Vec::new();

        if self.has_unsafe_ownership_transfer() {
            transfers.push(AccessControlIssue {
                issue_type: "Unsafe Ownership Transfer".to_string(),
                location: 0,
                description: "Ownership can be transferred without safeguards".to_string(),
                severity: SecuritySeverity::Critical,
            });
        }

        transfers
    }

    fn check_timelock_evolution(&self) -> Vec<AccessControlIssue> {
        let mut issues = Vec::new();

        if self.has_timelock_degradation() {
            issues.push(AccessControlIssue {
                issue_type: "Timelock Degradation".to_string(),
                location: 0,
                description: "Timelock protections can be weakened over time".to_string(),
                severity: SecuritySeverity::High,
            });
        }

        issues
    }

    fn has_privilege_escalation_path(&self) -> bool {
        // Function that modifies access control without proper checks
        let has_role_grant = self.bytecode.windows(4).any(|w| w == &[0x60, 0x00, 0x55, 0x00]); // PUSH 0, SSTORE
        let has_caller_check = self.bytecode.contains(&0x33); // CALLER
        
        has_role_grant && !has_caller_check
    }

    fn has_unsafe_role_transition(&self) -> bool {
        // Role assignment without multi-sig or timelock
        let has_role_change = self.bytecode.contains(&0x55); // SSTORE
        let has_multisig = self.bytecode.iter().filter(|&&b| b == 0x33).count() > 1; // Multiple CALLER checks
        
        has_role_change && !has_multisig
    }

    fn has_unsafe_ownership_transfer(&self) -> bool {
        // Transfer ownership function without two-step process
        let has_ownership_change = self.bytecode.contains(&0x55);
        let has_pending_owner = self.bytecode.windows(2).any(|w| w == &[0x54, 0x55]); // SLOAD, SSTORE (pending pattern)
        
        has_ownership_change && !has_pending_owner
    }

    fn has_timelock_degradation(&self) -> bool {
        // Timelock delay can be reduced without restriction
        let has_delay_change = self.bytecode.contains(&0x55); // SSTORE
        let has_minimum_check = self.bytecode.contains(&0x10); // LT (less than minimum)
        
        has_delay_change && !has_minimum_check
    }

    pub fn calculate_access_control_risk(&self) -> f64 {
        let issues = self.validate_access_control_evolution();
        let critical = issues.iter().filter(|i| matches!(i.severity, SecuritySeverity::Critical)).count();
        let high = issues.iter().filter(|i| matches!(i.severity, SecuritySeverity::High)).count();
        
        (critical as f64 * 1.0) + (high as f64 * 0.7)
    }
}
