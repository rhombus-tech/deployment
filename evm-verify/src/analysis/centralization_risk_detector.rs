// Centralization Risk Detector
// Detects single points of failure and centralized control patterns

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CentralizationVulnerability {
    pub risk_type: CentralizationRisk,
    pub severity: SecuritySeverity,
    pub description: String,
    pub control_addresses: Vec<String>,
    pub affected_functions: Vec<FunctionControl>,
    pub decentralization_score: f32, // 0.0 = fully centralized, 1.0 = fully decentralized
    pub single_point_of_failure: bool,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CentralizationRisk {
    SingleOwnerControl,           // 1 address controls everything
    WeakMultisig,                 // <5 signers or <60% threshold
    NoTimelock,                   // Instant upgrades/changes
    AdminCanStealFunds,           // Emergency withdraw to admin
    CentralizedOracle,            // Single oracle source
    UpgradeableWithoutGovernance, // No governance vote for upgrades
    PauseWithoutTimebound,        // Can pause forever
    UnilateralParameterControl,   // Admin can change critical params
    MintingCentralization,        // Unlimited minting by owner
    FeeControlCentralization,     // Can set fees to 100%
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionControl {
    pub selector: [u8; 4],
    pub function_name: String,
    pub control_type: ControlType,
    pub controller_count: usize,
    pub requires_timelock: bool,
    pub can_steal_funds: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlType {
    SingleAddress,      // onlyOwner
    Multisig,          // 2/3, 3/5, etc
    Governance,        // Token vote
    Timelock,          // Delayed execution
    Immutable,         // No control
}

pub struct CentralizationRiskDetector {
    bytecode: Vec<u8>,
}

impl CentralizationRiskDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn analyze(&self) -> Vec<CentralizationVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_single_owner_control());
        vulnerabilities.extend(self.detect_weak_multisig());
        vulnerabilities.extend(self.detect_no_timelock());
        vulnerabilities.extend(self.detect_admin_can_steal_funds());
        vulnerabilities.extend(self.detect_centralized_oracle());
        vulnerabilities.extend(self.detect_upgradeable_without_governance());
        vulnerabilities.extend(self.detect_pause_without_timebound());
        vulnerabilities.extend(self.detect_parameter_control());
        vulnerabilities.extend(self.detect_minting_centralization());

        vulnerabilities
    }

    fn detect_single_owner_control(&self) -> Vec<CentralizationVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: onlyOwner modifier (CALLER, SLOAD owner_slot, EQ, ISZERO, REVERT)
        let has_only_owner = self.has_pattern(&[
            0x33, // CALLER
            0x54, // SLOAD (owner slot)
            0x14, // EQ
            0x15, // ISZERO
            0xFD, // REVERT
        ]);

        if has_only_owner {
            // Count critical functions with onlyOwner
            let critical_functions = self.count_owner_controlled_functions();
            
            if critical_functions >= 5 {
                vulns.push(CentralizationVulnerability {
                    risk_type: CentralizationRisk::SingleOwnerControl,
                    severity: SecuritySeverity::High,
                    description: format!(
                        "Single owner controls {} critical functions. Complete centralization.",
                        critical_functions
                    ),
                    control_addresses: vec!["owner_address".to_string()],
                    affected_functions: self.get_owner_controlled_functions(),
                    decentralization_score: 0.1,
                    single_point_of_failure: true,
                    remediation: "Implement multi-sig (5/9) + 48h timelock + governance for critical functions".to_string(),
                });
            }
        }

        vulns
    }

    fn detect_weak_multisig(&self) -> Vec<CentralizationVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: Multi-sig threshold check
        // SLOAD signers_count, PUSH1 threshold, LT
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x54 { // SLOAD
                // Check if followed by threshold comparison
                if i + 5 < self.bytecode.len() {
                    if self.bytecode[i + 2] == 0x60 { // PUSH1 threshold
                        let threshold = self.bytecode[i + 3] as usize;
                        
                        // Detect total signers (look for array length)
                        let total_signers = self.estimate_signer_count();
                        
                        if total_signers > 0 {
                            let threshold_percentage = (threshold as f32 / total_signers as f32) * 100.0;
                            
                            // Red flags: <5 signers OR <60% threshold
                            if total_signers < 5 || threshold_percentage < 60.0 {
                                vulns.push(CentralizationVulnerability {
                                    risk_type: CentralizationRisk::WeakMultisig,
                                    severity: if total_signers < 3 {
                                        SecuritySeverity::Critical
                                    } else {
                                        SecuritySeverity::High
                                    },
                                    description: format!(
                                        "Weak multi-sig: {}/{} signers ({}% threshold). Easily compromised.",
                                        threshold, total_signers, threshold_percentage
                                    ),
                                    control_addresses: vec![format!("{}_signers", total_signers)],
                                    affected_functions: vec![],
                                    decentralization_score: 0.3,
                                    single_point_of_failure: threshold < 3,
                                    remediation: format!(
                                        "Increase to 5/9 multi-sig (minimum 5 signers, 60% threshold). Current {}/{} is insufficient.",
                                        threshold, total_signers
                                    ),
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        vulns
    }

    fn detect_no_timelock(&self) -> Vec<CentralizationVulnerability> {
        let mut vulns = Vec::new();

        // Check for upgradeTo function without timelock
        let has_upgrade = self.has_function_selector(&[0x36, 0x57, 0x84, 0x30]); // upgradeTo()
        
        if has_upgrade {
            // Check for TIMESTAMP comparison (timelock pattern)
            let has_timelock = self.has_pattern(&[
                0x42, // TIMESTAMP
                0x54, // SLOAD (stored execution time)
                0x11, // GT (must be after delay)
            ]);

            if !has_timelock {
                vulns.push(CentralizationVulnerability {
                    risk_type: CentralizationRisk::NoTimelock,
                    severity: SecuritySeverity::Critical,
                    description: "Upgradeable contract with NO TIMELOCK. Admin can rug pull instantly.".to_string(),
                    control_addresses: vec!["admin".to_string()],
                    affected_functions: vec![FunctionControl {
                        selector: [0x36, 0x57, 0x84, 0x30],
                        function_name: "upgradeTo()".to_string(),
                        control_type: ControlType::SingleAddress,
                        controller_count: 1,
                        requires_timelock: false,
                        can_steal_funds: true,
                    }],
                    decentralization_score: 0.0,
                    single_point_of_failure: true,
                    remediation: "Add 48-hour minimum timelock before upgrade execution. Users need time to exit.".to_string(),
                });
            } else {
                // Check timelock duration
                let delay_hours = self.estimate_timelock_delay();
                if delay_hours < 24 {
                    vulns.push(CentralizationVulnerability {
                        risk_type: CentralizationRisk::NoTimelock,
                        severity: SecuritySeverity::High,
                        description: format!(
                            "Timelock exists but only {}h delay. Insufficient for users to react.",
                            delay_hours
                        ),
                        control_addresses: vec!["admin".to_string()],
                        affected_functions: vec![],
                        decentralization_score: 0.4,
                        single_point_of_failure: false,
                        remediation: "Increase timelock to minimum 48 hours (recommended 72h for high-value protocols).".to_string(),
                    });
                }
            }
        }

        vulns
    }

    fn detect_admin_can_steal_funds(&self) -> Vec<CentralizationVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: Admin function that calls SELFDESTRUCT or transfers all balance
        // Look for: onlyOwner + BALANCE + CALL (transfer to owner)
        
        // Check for emergency withdraw pattern
        let dangerous_patterns = vec![
            // Pattern 1: emergencyWithdraw() with onlyOwner
            ([0x5f, 0xd8, 0xc7, 0x10], "emergencyWithdraw()"),
            // Pattern 2: withdraw(address) with no amount check
            ([0x51, 0xcf, 0xf8, 0xd9], "withdraw(address)"),
            // Pattern 3: recoverERC20() with no token whitelist
            ([0x8d, 0x8f, 0x69, 0x22], "recoverERC20()"),
        ];

        for (selector, name) in dangerous_patterns {
            if self.has_function_selector(&selector) {
                // Check if it has owner check
                let near_owner_check = self.has_owner_check_near_selector(&selector);
                
                // Check if it transfers balance
                let transfers_balance = self.function_transfers_balance(&selector);
                
                if near_owner_check && transfers_balance {
                    vulns.push(CentralizationVulnerability {
                        risk_type: CentralizationRisk::AdminCanStealFunds,
                        severity: SecuritySeverity::Critical,
                        description: format!(
                            "Admin function {} can drain ALL user funds. This is a rug pull vector.",
                            name
                        ),
                        control_addresses: vec!["owner".to_string()],
                        affected_functions: vec![FunctionControl {
                            selector,
                            function_name: name.to_string(),
                            control_type: ControlType::SingleAddress,
                            controller_count: 1,
                            requires_timelock: false,
                            can_steal_funds: true,
                        }],
                        decentralization_score: 0.0,
                        single_point_of_failure: true,
                        remediation: format!(
                            "REMOVE {}. If needed for stuck funds, add: 1) Multi-sig, 2) 7-day timelock, 3) Only recover specific tokens with proof",
                            name
                        ),
                    });
                }
            }
        }

        vulns
    }

    fn detect_centralized_oracle(&self) -> Vec<CentralizationVulnerability> {
        let mut vulns = Vec::new();

        // Pattern: Single STATICCALL to oracle without fallback
        let oracle_calls = self.count_oracle_staticcalls();
        
        if oracle_calls == 1 {
            vulns.push(CentralizationVulnerability {
                risk_type: CentralizationRisk::CentralizedOracle,
                severity: SecuritySeverity::High,
                description: "Single oracle source with no fallback. Oracle failure = protocol failure.".to_string(),
                control_addresses: vec!["oracle_address".to_string()],
                affected_functions: vec![],
                decentralization_score: 0.2,
                single_point_of_failure: true,
                remediation: "Use 3+ oracle sources with median/TWAP aggregation. Add staleness checks (<1h).".to_string(),
            });
        }

        vulns
    }

    fn detect_upgradeable_without_governance(&self) -> Vec<CentralizationVulnerability> {
        let mut vulns = Vec::new();

        let has_upgrade = self.has_function_selector(&[0x36, 0x57, 0x84, 0x30]);
        let has_governance_vote = self.has_pattern(&[
            0x54, // SLOAD (proposal state)
            0x60, 0x04, // PUSH1 4 (Succeeded state)
            0x14, // EQ
        ]);

        if has_upgrade && !has_governance_vote {
            vulns.push(CentralizationVulnerability {
                risk_type: CentralizationRisk::UpgradeableWithoutGovernance,
                severity: SecuritySeverity::High,
                description: "Contract upgradeable but no governance vote required. Admin unilateral control.".to_string(),
                control_addresses: vec!["admin".to_string()],
                affected_functions: vec![],
                decentralization_score: 0.2,
                single_point_of_failure: true,
                remediation: "Require token-weighted governance vote + 48h timelock before any upgrade.".to_string(),
            });
        }

        vulns
    }

    fn detect_pause_without_timebound(&self) -> Vec<CentralizationVulnerability> {
        let mut vulns = Vec::new();

        // Check for pause() function
        let has_pause = self.has_function_selector(&[0x8d, 0xa5, 0xcb, 0x5b]); // pause()
        
        if has_pause {
            // Check if there's an automatic unpause after time
            let has_auto_unpause = self.has_pattern(&[
                0x42, // TIMESTAMP
                0x54, // SLOAD (pause_end_time)
                0x11, // GT (time > pause_end)
            ]);

            if !has_auto_unpause {
                vulns.push(CentralizationVulnerability {
                    risk_type: CentralizationRisk::PauseWithoutTimebound,
                    severity: SecuritySeverity::Medium,
                    description: "Admin can pause protocol indefinitely. No automatic unpause mechanism.".to_string(),
                    control_addresses: vec!["admin".to_string()],
                    affected_functions: vec![],
                    decentralization_score: 0.5,
                    single_point_of_failure: false,
                    remediation: "Add maximum pause duration (7 days) with automatic unpause. Require governance vote to re-pause.".to_string(),
                });
            }
        }

        vulns
    }

    fn detect_parameter_control(&self) -> Vec<CentralizationVulnerability> {
        let mut vulns = Vec::new();

        // Check for setFee, setRate, setLimit functions with owner control
        let param_functions = vec![
            ([0x69, 0xfe, 0x0e, 0x2d], "setFee()"),
            ([0x34, 0xfc, 0xf4, 0x37], "setRate()"),
            ([0x7f, 0x64, 0x97, 0x83], "setLimit()"),
        ];

        let mut controlled_params = Vec::new();
        
        for (selector, name) in param_functions {
            if self.has_function_selector(&selector) && self.has_owner_check_near_selector(&selector) {
                controlled_params.push(name);
            }
        }

        if controlled_params.len() >= 2 {
            vulns.push(CentralizationVulnerability {
                risk_type: CentralizationRisk::UnilateralParameterControl,
                severity: SecuritySeverity::Medium,
                description: format!(
                    "Admin can unilaterally change {} critical parameters. No limits or governance.",
                    controlled_params.len()
                ),
                control_addresses: vec!["admin".to_string()],
                affected_functions: vec![],
                decentralization_score: 0.4,
                single_point_of_failure: false,
                remediation: "Add: 1) Parameter bounds (e.g., fee <10%), 2) 24h timelock, 3) Governance for >5% changes".to_string(),
            });
        }

        vulns
    }

    fn detect_minting_centralization(&self) -> Vec<CentralizationVulnerability> {
        let mut vulns = Vec::new();

        // Check for mint() with owner control and no cap
        let has_mint = self.has_function_selector(&[0x40, 0xc1, 0x0f, 0x19]); // mint()
        
        if has_mint && self.has_owner_check_near_selector(&[0x40, 0xc1, 0x0f, 0x19]) {
            // Check for supply cap
            let has_cap = self.has_pattern(&[
                0x54, // SLOAD totalSupply
                0x54, // SLOAD maxSupply
                0x11, // GT
            ]);

            if !has_cap {
                vulns.push(CentralizationVulnerability {
                    risk_type: CentralizationRisk::MintingCentralization,
                    severity: SecuritySeverity::High,
                    description: "Admin can mint unlimited tokens. No supply cap = infinite dilution risk.".to_string(),
                    control_addresses: vec!["minter".to_string()],
                    affected_functions: vec![FunctionControl {
                        selector: [0x40, 0xc1, 0x0f, 0x19],
                        function_name: "mint()".to_string(),
                        control_type: ControlType::SingleAddress,
                        controller_count: 1,
                        requires_timelock: false,
                        can_steal_funds: true,
                    }],
                    decentralization_score: 0.1,
                    single_point_of_failure: true,
                    remediation: "Add hard supply cap OR require governance vote + 48h timelock for minting.".to_string(),
                });
            }
        }

        vulns
    }

    // === HELPER METHODS ===

    fn has_pattern(&self, pattern: &[u8]) -> bool {
        self.bytecode.windows(pattern.len()).any(|window| window == pattern)
    }

    fn has_function_selector(&self, selector: &[u8; 4]) -> bool {
        self.bytecode.windows(4).any(|window| window == selector)
    }

    fn has_owner_check_near_selector(&self, selector: &[u8; 4]) -> bool {
        // Find selector, check next 20 bytes for owner check pattern
        for i in 0..self.bytecode.len().saturating_sub(24) {
            if &self.bytecode[i..i+4] == selector {
                // Look for CALLER, SLOAD, EQ pattern within next 20 bytes
                for j in i..i.min(self.bytecode.len().saturating_sub(3)) {
                    if self.bytecode[j] == 0x33 && self.bytecode[j+1] == 0x54 {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn function_transfers_balance(&self, selector: &[u8; 4]) -> bool {
        // Check if function contains BALANCE + CALL pattern
        for i in 0..self.bytecode.len().saturating_sub(24) {
            if &self.bytecode[i..i+4] == selector {
                // Look for BALANCE (0x47) followed by CALL (0xF1) within 50 bytes
                for j in i..i.min(self.bytecode.len().saturating_sub(10)) {
                    if self.bytecode[j] == 0x47 { // BALANCE
                        for k in j..j.min(self.bytecode.len()).min(j+50) {
                            if self.bytecode[k] == 0xF1 { // CALL
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    fn count_owner_controlled_functions(&self) -> usize {
        let mut count = 0;
        // Count function selectors followed by owner check
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x63 { // PUSH4 (function selector)
                // Check if followed by owner check within 20 bytes
                for j in i..i.min(self.bytecode.len().saturating_sub(3)).min(i+20) {
                    if self.bytecode[j] == 0x33 && self.bytecode[j+1] == 0x54 {
                        count += 1;
                        break;
                    }
                }
            }
        }
        count
    }

    fn get_owner_controlled_functions(&self) -> Vec<FunctionControl> {
        vec![] // Placeholder
    }

    fn estimate_signer_count(&self) -> usize {
        // Heuristic: Look for array length SLOAD patterns
        // This is a simplified estimate
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x54 { // SLOAD
                if i + 5 < self.bytecode.len() {
                    // Check if next value is reasonable signer count (3-15)
                    if self.bytecode[i + 2] == 0x60 { // PUSH1
                        let val = self.bytecode[i + 3] as usize;
                        if val >= 3 && val <= 15 {
                            return val;
                        }
                    }
                }
            }
        }
        0
    }

    fn estimate_timelock_delay(&self) -> usize {
        // Look for time delay constants (in seconds)
        // 86400 = 1 day, 172800 = 2 days, etc.
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x62 { // PUSH3
                let value = u32::from_be_bytes([
                    0,
                    self.bytecode[i+1],
                    self.bytecode[i+2],
                    self.bytecode[i+3],
                ]);
                
                if value > 0 && value < 1000000 {
                    return (value / 3600) as usize; // Convert to hours
                }
            }
        }
        0
    }

    fn count_oracle_staticcalls(&self) -> usize {
        let mut count = 0;
        for byte in &self.bytecode {
            if *byte == 0xFA { // STATICCALL
                count += 1;
            }
        }
        count
    }
}

/// Calculate overall decentralization score
pub fn calculate_decentralization_score(vulnerabilities: &[CentralizationVulnerability]) -> DecentralizationReport {
    let critical_count = vulnerabilities.iter()
        .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
        .count();
    
    let has_single_point_of_failure = vulnerabilities.iter()
        .any(|v| v.single_point_of_failure);
    
    let avg_score = if vulnerabilities.is_empty() {
        1.0
    } else {
        vulnerabilities.iter()
            .map(|v| v.decentralization_score)
            .sum::<f32>() / vulnerabilities.len() as f32
    };

    let risk_level = if has_single_point_of_failure {
        "CRITICAL - Single point of failure exists".to_string()
    } else if critical_count > 0 {
        "HIGH - Multiple centralization risks".to_string()
    } else if avg_score < 0.5 {
        "MEDIUM - Significant centralization".to_string()
    } else {
        "LOW - Reasonable decentralization".to_string()
    };

    DecentralizationReport {
        total_risks: vulnerabilities.len(),
        critical_risks: critical_count,
        single_point_of_failure: has_single_point_of_failure,
        decentralization_score: avg_score,
        risk_level,
        recommendation: if has_single_point_of_failure {
            "URGENT: Remove single points of failure before launch. This is a rug pull risk.".to_string()
        } else if critical_count > 0 {
            "HIGH PRIORITY: Address centralization risks with multi-sig + timelock.".to_string()
        } else {
            "Consider further decentralization with governance tokens and protocol-owned liquidity.".to_string()
        },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecentralizationReport {
    pub total_risks: usize,
    pub critical_risks: usize,
    pub single_point_of_failure: bool,
    pub decentralization_score: f32, // 0.0-1.0
    pub risk_level: String,
    pub recommendation: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_owner_detection() {
        // onlyOwner pattern: CALLER SLOAD EQ ISZERO REVERT
        let bytecode = vec![
            0x33, // CALLER
            0x54, // SLOAD
            0x14, // EQ
            0x15, // ISZERO
            0xFD, // REVERT
        ];
        
        let detector = CentralizationRiskDetector::new(bytecode);
        let vulns = detector.detect_single_owner_control();
        
        assert!(vulns.len() > 0, "Should detect single owner control");
    }

    #[test]
    fn test_no_timelock_detection() {
        // upgradeTo without timelock
        let bytecode = vec![
            0x36, 0x57, 0x84, 0x30, // upgradeTo selector
            0x00, 0x00, 0x00, 0x00,
        ];
        
        let detector = CentralizationRiskDetector::new(bytecode);
        let vulns = detector.detect_no_timelock();
        
        assert!(vulns.len() > 0, "Should detect missing timelock");
    }
}
