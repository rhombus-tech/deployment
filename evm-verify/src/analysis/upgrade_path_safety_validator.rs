/// Upgrade Path Safety Validator
/// Validates that contract upgrade paths maintain security and don't introduce vulnerabilities
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone)]
pub struct UpgradePathSafetyValidator {
    bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct UpgradeSafetyIssue {
    pub issue_type: String,
    pub location: usize,
    pub description: String,
    pub potential_impact: String,
    pub severity: SecuritySeverity,
}

impl UpgradePathSafetyValidator {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn validate_upgrade_safety(&self) -> Vec<UpgradeSafetyIssue> {
        let mut issues = Vec::new();

        // Check for storage layout incompatibilities
        issues.extend(self.check_storage_layout_safety());
        
        // Check for initialization vulnerabilities
        issues.extend(self.check_initialization_safety());
        
        // Check for upgrade authorization issues
        issues.extend(self.check_upgrade_authorization());
        
        // Check for state migration risks
        issues.extend(self.check_state_migration_safety());

        issues
    }

    fn check_storage_layout_safety(&self) -> Vec<UpgradeSafetyIssue> {
        let mut issues = Vec::new();

        if self.has_storage_collision_risk() {
            issues.push(UpgradeSafetyIssue {
                issue_type: "Storage Collision Risk".to_string(),
                location: 0,
                description: "Upgrade may cause storage slot collisions".to_string(),
                potential_impact: "Data corruption or loss".to_string(),
                severity: SecuritySeverity::Critical,
            });
        }

        issues
    }

    fn check_initialization_safety(&self) -> Vec<UpgradeSafetyIssue> {
        let mut issues = Vec::new();

        if self.has_reinitialization_vulnerability() {
            issues.push(UpgradeSafetyIssue {
                issue_type: "Reinitialization Vulnerability".to_string(),
                location: 0,
                description: "Initialize function can be called multiple times".to_string(),
                potential_impact: "Attacker can reset critical state".to_string(),
                severity: SecuritySeverity::Critical,
            });
        }

        issues
    }

    fn check_upgrade_authorization(&self) -> Vec<UpgradeSafetyIssue> {
        let mut issues = Vec::new();

        if self.has_weak_upgrade_authorization() {
            issues.push(UpgradeSafetyIssue {
                issue_type: "Weak Upgrade Authorization".to_string(),
                location: 0,
                description: "Upgrade authorization is insufficiently protected".to_string(),
                potential_impact: "Unauthorized upgrade to malicious implementation".to_string(),
                severity: SecuritySeverity::Critical,
            });
        }

        issues
    }

    fn check_state_migration_safety(&self) -> Vec<UpgradeSafetyIssue> {
        let mut issues = Vec::new();

        if self.has_unsafe_state_migration() {
            issues.push(UpgradeSafetyIssue {
                issue_type: "Unsafe State Migration".to_string(),
                location: 0,
                description: "State migration lacks atomic guarantees".to_string(),
                potential_impact: "Partial migration leading to inconsistent state".to_string(),
                severity: SecuritySeverity::High,
            });
        }

        issues
    }

    fn has_storage_collision_risk(&self) -> bool {
        // Multiple SSTORE operations to same slot without namespacing
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let has_namespace = self.bytecode.windows(32).any(|w| w.iter().all(|&b| b != 0x00)); // ERC-1967 pattern
        
        sstore_count > 5 && !has_namespace
    }

    fn has_reinitialization_vulnerability(&self) -> bool {
        // Initialize function without initialized flag check
        let has_sstore = self.bytecode.contains(&0x55);
        let has_initialized_check = self.bytecode.windows(2).any(|w| w == &[0x54, 0x15]); // SLOAD + ISZERO
        
        has_sstore && !has_initialized_check
    }

    fn has_weak_upgrade_authorization(&self) -> bool {
        // DELEGATECALL without proper access control
        let has_delegatecall = self.bytecode.contains(&0xf4);
        let has_owner_check = self.bytecode.windows(2).any(|w| w == &[0x33, 0x14]); // CALLER + EQ
        
        has_delegatecall && !has_owner_check
    }

    fn has_unsafe_state_migration(&self) -> bool {
        // State migration without atomic guarantees
        let migration_operations = self.bytecode.iter()
            .filter(|&&b| b == 0x55 || b == 0x54) // SSTORE or SLOAD
            .count();
        let has_revert_on_failure = self.bytecode.contains(&0xfd); // REVERT
        
        migration_operations > 10 && !has_revert_on_failure
    }

    pub fn calculate_upgrade_risk_score(&self) -> f64 {
        let issues = self.validate_upgrade_safety();
        let critical = issues.iter().filter(|i| matches!(i.severity, SecuritySeverity::Critical)).count();
        let high = issues.iter().filter(|i| matches!(i.severity, SecuritySeverity::High)).count();
        
        (critical as f64 * 1.0) + (high as f64 * 0.6)
    }

    pub fn get_critical_upgrade_issues(&self) -> Vec<String> {
        self.validate_upgrade_safety()
            .iter()
            .filter(|i| matches!(i.severity, SecuritySeverity::Critical))
            .map(|i| format!("{}: {}", i.issue_type, i.description))
            .collect()
    }
}
