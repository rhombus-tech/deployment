/// Stale State After Upgrade Detector
/// Detects when upgradeable contracts don't properly migrate state,
/// leading to stale values causing incorrect behavior post-upgrade
///
/// Common in proxy patterns where storage layout changes

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaleStateVulnerability {
    pub vulnerability_type: StaleStateIssue,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StaleStateIssue {
    NoStateMigration,              // Upgrade without migration function
    IncompleteMigration,           // Migration doesn't cover all state
    StaleStorageRead,              // Reading unmigrated storage
    VersionMismatch,               // No version check before using state
}

pub struct StaleStateUpgradeDetector {
    bytecode: Vec<u8>,
}

impl StaleStateUpgradeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<StaleStateVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_upgradeable_contract() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_missing_migration());
        vulnerabilities.extend(self.detect_no_version_check());

        vulnerabilities
    }

    fn is_upgradeable_contract(&self) -> bool {
        // Look for: upgradeTo, upgradeToAndCall, initialize
        let upgrade_sigs = [
            [0x3d, 0x18, 0xb9, 0x12], // upgradeTo
            [0x4f, 0x1e, 0xf2, 0x86], // upgradeToAndCall
        ];
        
        upgrade_sigs.iter().any(|sig| {
            self.bytecode.windows(4).any(|w| w == sig)
        })
    }

    fn detect_missing_migration(&self) -> Vec<StaleStateVulnerability> {
        let mut vulnerabilities = Vec::new();

        let has_initialize = self.has_initialize_function();
        let has_reinitializer = self.has_reinitializer();
        
        if has_initialize && !has_reinitializer {
            vulnerabilities.push(StaleStateVulnerability {
                vulnerability_type: StaleStateIssue::NoStateMigration,
                severity: SecuritySeverity::High,
                confidence: 0.75,
                description:
                    "Upgradeable contract has initialize() but no reinitializer for upgrades. \
                    New state variables won't be initialized after upgrade.".to_string(),
                exploit_scenario:
                    "Stale State Exploit:\n\
                     1. V1 contract deployed with state variables A, B\n\
                     2. Upgrade to V2 adds new state variable C\n\
                     3. No migration function to initialize C\n\
                     4. C remains at default value (0)\n\
                     5. Logic assumes C is initialized → incorrect behavior\n\n\
                     Fix: Add reinitializer(2) function for V2".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }

    fn detect_no_version_check(&self) -> Vec<StaleStateVulnerability> {
        let mut vulnerabilities = Vec::new();

        let has_version_storage = self.has_version_variable();
        
        if !has_version_storage {
            vulnerabilities.push(StaleStateVulnerability {
                vulnerability_type: StaleStateIssue::VersionMismatch,
                severity: SecuritySeverity::Medium,
                confidence: 0.70,
                description:
                    "No version variable detected. Contract can't verify state migration status.".to_string(),
                exploit_scenario:
                    "Version Confusion:\n\
                     1. Multiple upgrades without version tracking\n\
                     2. Can't determine which migration ran\n\
                     3. State may be partially migrated\n\
                     4. Logic executes with inconsistent state\n\n\
                     Fix: uint256 public version; in reinitializer".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }

    fn has_initialize_function(&self) -> bool {
        // initialize() selector: 0x8129fc1c
        self.bytecode.windows(4).any(|w| w == [0x81, 0x29, 0xfc, 0x1c])
    }

    fn has_reinitializer(&self) -> bool {
        // OpenZeppelin reinitializer uses _initialized storage slot
        // Look for comparison with version number
        let mut version_checks = 0;
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x54 && // SLOAD (_initialized)
               self.bytecode.get(i + 1) == Some(&0x10) { // LT (version check)
                version_checks += 1;
            }
        }
        
        version_checks >= 2 // At least 2 version checks = has reinitializer
    }

    fn has_version_variable(&self) -> bool {
        // Look for storage slot labeled "version" or explicit version checks
        // Heuristic: Multiple SLOAD followed by comparisons
        
        self.bytecode.windows(3)
            .filter(|w| w[0] == 0x54 && matches!(w[1], 0x10 | 0x11 | 0x14))
            .count() >= 3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_migration() {
        let bytecode = vec![
            0x3d, 0x18, 0xb9, 0x12, // upgradeTo selector
            0x81, 0x29, 0xfc, 0x1c, // initialize selector
            // No reinitializer pattern
        ];
        
        let detector = StaleStateUpgradeDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty());
    }
}
