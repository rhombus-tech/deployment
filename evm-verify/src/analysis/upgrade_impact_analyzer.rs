/// Upgrade Impact Analyzer
/// Predicts security impact of proposed contract upgrades
use crate::bytecode::SecuritySeverity;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct UpgradeImpactAnalyzer {
    old_bytecode: Vec<u8>,
    new_bytecode: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct UpgradeImpact {
    pub impact_type: ImpactType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub affected_functions: Vec<String>,
    pub risk_score: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ImpactType {
    StorageLayoutChange,      // Storage slot collision
    FunctionSignatureChange,  // Breaking ABI changes
    AccessControlChange,      // Permission changes
    LogicChange,              // Core logic modifications
    SecurityDowngrade,        // Removed security features
    StateBreaking,            // Incompatible state migration
}

impl UpgradeImpactAnalyzer {
    pub fn new(old_bytecode: Vec<u8>, new_bytecode: Vec<u8>) -> Self {
        Self {
            old_bytecode,
            new_bytecode,
        }
    }

    pub fn analyze_upgrade_impact(&self) -> Vec<UpgradeImpact> {
        let mut impacts = Vec::new();

        // Check storage layout changes
        impacts.extend(self.analyze_storage_changes());
        
        // Check function signature changes
        impacts.extend(self.analyze_function_changes());
        
        // Check access control changes
        impacts.extend(self.analyze_access_control_changes());
        
        // Check security feature changes
        impacts.extend(self.analyze_security_changes());
        
        // Check state compatibility
        impacts.extend(self.analyze_state_compatibility());

        impacts
    }

    fn analyze_storage_changes(&self) -> Vec<UpgradeImpact> {
        let mut impacts = Vec::new();

        // Detect storage layout changes by comparing SSTORE patterns
        let old_sstores = self.count_storage_operations(&self.old_bytecode);
        let new_sstores = self.count_storage_operations(&self.new_bytecode);

        if old_sstores != new_sstores {
            impacts.push(UpgradeImpact {
                impact_type: ImpactType::StorageLayoutChange,
                severity: SecuritySeverity::Critical,
                description: format!(
                    "Storage layout changed: {} -> {} SSTORE operations. Risk of storage collision!",
                    old_sstores, new_sstores
                ),
                affected_functions: vec!["All state-modifying functions".to_string()],
                risk_score: 9.5,
            });
        }

        // Check for new storage slots
        if new_sstores > old_sstores {
            impacts.push(UpgradeImpact {
                impact_type: ImpactType::StorageLayoutChange,
                severity: SecuritySeverity::High,
                description: format!(
                    "New storage variables added. Ensure storage gap usage or append-only pattern."
                ),
                affected_functions: vec![],
                risk_score: 7.0,
            });
        }

        impacts
    }

    fn analyze_function_changes(&self) -> Vec<UpgradeImpact> {
        let mut impacts = Vec::new();

        // Detect function selector changes
        let old_selectors = self.extract_function_selectors(&self.old_bytecode);
        let new_selectors = self.extract_function_selectors(&self.new_bytecode);

        // Removed functions
        for selector in &old_selectors {
            if !new_selectors.contains(selector) {
                impacts.push(UpgradeImpact {
                    impact_type: ImpactType::FunctionSignatureChange,
                    severity: SecuritySeverity::High,
                    description: format!("Function removed: selector {:#x}", selector),
                    affected_functions: vec![format!("Function_{:#x}", selector)],
                    risk_score: 8.0,
                });
            }
        }

        // New functions
        for selector in &new_selectors {
            if !old_selectors.contains(selector) {
                impacts.push(UpgradeImpact {
                    impact_type: ImpactType::FunctionSignatureChange,
                    severity: SecuritySeverity::Medium,
                    description: format!("New function added: selector {:#x}", selector),
                    affected_functions: vec![format!("Function_{:#x}", selector)],
                    risk_score: 5.0,
                });
            }
        }

        impacts
    }

    fn analyze_access_control_changes(&self) -> Vec<UpgradeImpact> {
        let mut impacts = Vec::new();

        // Check for CALLER (0x33) + EQ (0x14) patterns (access control checks)
        let old_checks = self.count_access_checks(&self.old_bytecode);
        let new_checks = self.count_access_checks(&self.new_bytecode);

        if new_checks < old_checks {
            impacts.push(UpgradeImpact {
                impact_type: ImpactType::AccessControlChange,
                severity: SecuritySeverity::Critical,
                description: format!(
                    "Access control checks reduced: {} -> {}. Possible privilege escalation!",
                    old_checks, new_checks
                ),
                affected_functions: vec!["Protected functions".to_string()],
                risk_score: 10.0,
            });
        }

        if new_checks > old_checks {
            impacts.push(UpgradeImpact {
                impact_type: ImpactType::AccessControlChange,
                severity: SecuritySeverity::Low,
                description: format!(
                    "Access control checks increased: {} -> {}. Security improved.",
                    old_checks, new_checks
                ),
                affected_functions: vec![],
                risk_score: 2.0,
            });
        }

        impacts
    }

    fn analyze_security_changes(&self) -> Vec<UpgradeImpact> {
        let mut impacts = Vec::new();

        // Check for reentrancy guards (SLOAD + ISZERO pattern)
        let old_guards = self.count_reentrancy_guards(&self.old_bytecode);
        let new_guards = self.count_reentrancy_guards(&self.new_bytecode);

        if new_guards < old_guards {
            impacts.push(UpgradeImpact {
                impact_type: ImpactType::SecurityDowngrade,
                severity: SecuritySeverity::Critical,
                description: "Reentrancy guards removed! Critical security downgrade.".to_string(),
                affected_functions: vec!["External call functions".to_string()],
                risk_score: 9.8,
            });
        }

        // Check for SafeMath removal (common in 0.8.0+ upgrades)
        let old_safe = self.has_safemath(&self.old_bytecode);
        let new_safe = self.has_safemath(&self.new_bytecode);

        if old_safe && !new_safe {
            // This might be okay if upgrading to Solidity 0.8.0+
            impacts.push(UpgradeImpact {
                impact_type: ImpactType::LogicChange,
                severity: SecuritySeverity::Medium,
                description: "SafeMath removed. Ensure Solidity 0.8.0+ for built-in overflow protection.".to_string(),
                affected_functions: vec!["Arithmetic operations".to_string()],
                risk_score: 6.0,
            });
        }

        impacts
    }

    fn analyze_state_compatibility(&self) -> Vec<UpgradeImpact> {
        let mut impacts = Vec::new();

        // Check if constructor is present in new code (bad for upgradeable contracts)
        if self.has_constructor(&self.new_bytecode) {
            impacts.push(UpgradeImpact {
                impact_type: ImpactType::StateBreaking,
                severity: SecuritySeverity::Critical,
                description: "Constructor detected in upgradeable contract! Use initializer instead.".to_string(),
                affected_functions: vec!["constructor".to_string()],
                risk_score: 10.0,
            });
        }

        // Check for selfdestruct in new code (dangerous in upgradeable contracts)
        if self.has_selfdestruct(&self.new_bytecode) {
            impacts.push(UpgradeImpact {
                impact_type: ImpactType::StateBreaking,
                severity: SecuritySeverity::Critical,
                description: "SELFDESTRUCT detected! Can brick proxy permanently.".to_string(),
                affected_functions: vec!["Functions with selfdestruct".to_string()],
                risk_score: 10.0,
            });
        }

        impacts
    }

    // Helper methods
    fn count_storage_operations(&self, bytecode: &[u8]) -> usize {
        bytecode.iter().filter(|&&b| b == 0x55).count() // SSTORE count
    }

    fn extract_function_selectors(&self, bytecode: &[u8]) -> Vec<u32> {
        let mut selectors = Vec::new();
        
        // Look for PUSH4 (0x63) followed by 4 bytes (function selector pattern)
        for i in 0..bytecode.len().saturating_sub(5) {
            if bytecode[i] == 0x63 {
                let selector = u32::from_be_bytes([
                    bytecode[i + 1],
                    bytecode[i + 2],
                    bytecode[i + 3],
                    bytecode[i + 4],
                ]);
                selectors.push(selector);
            }
        }
        
        selectors.sort();
        selectors.dedup();
        selectors
    }

    fn count_access_checks(&self, bytecode: &[u8]) -> usize {
        bytecode.windows(2).filter(|w| w == &[0x33, 0x14]).count() // CALLER + EQ
    }

    fn count_reentrancy_guards(&self, bytecode: &[u8]) -> usize {
        bytecode.windows(2).filter(|w| w == &[0x54, 0x15]).count() // SLOAD + ISZERO
    }

    fn has_safemath(&self, bytecode: &[u8]) -> bool {
        // SafeMath typically has many ADD/SUB followed by checks
        bytecode.windows(2).any(|w| matches!(w, [0x01, 0x10] | [0x03, 0x10])) // ADD/SUB + LT
    }

    fn has_constructor(&self, bytecode: &[u8]) -> bool {
        // Constructor typically initializes storage at deployment
        // This is a simplified check
        bytecode.len() > 100 && bytecode.iter().filter(|&&b| b == 0x55).count() > 2
    }

    fn has_selfdestruct(&self, bytecode: &[u8]) -> bool {
        bytecode.contains(&0xff) // SELFDESTRUCT opcode
    }

    pub fn get_upgrade_risk_score(&self) -> f64 {
        let impacts = self.analyze_upgrade_impact();
        
        if impacts.is_empty() {
            return 0.0;
        }
        
        let total_risk: f64 = impacts.iter().map(|i| i.risk_score).sum();
        let max_risk = impacts.iter().map(|i| i.risk_score).fold(0.0, f64::max);
        
        // Return weighted score: 70% max risk, 30% average risk
        (max_risk * 0.7) + ((total_risk / impacts.len() as f64) * 0.3)
    }

    pub fn is_upgrade_safe(&self) -> bool {
        let impacts = self.analyze_upgrade_impact();
        
        // No critical impacts and risk score under threshold
        !impacts.iter().any(|i| matches!(i.severity, SecuritySeverity::Critical))
            && self.get_upgrade_risk_score() < 7.0
    }

    pub fn get_critical_blockers(&self) -> Vec<UpgradeImpact> {
        self.analyze_upgrade_impact()
            .into_iter()
            .filter(|i| matches!(i.severity, SecuritySeverity::Critical))
            .collect()
    }
}
