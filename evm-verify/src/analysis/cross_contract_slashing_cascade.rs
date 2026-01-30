/// Cross-Contract Slashing Cascade Detector
///
/// Detects vulnerabilities where slashing in one protocol cascades to others,
/// enabling coordinated attacks across multiple staking/validator systems.
///
/// Examples:
/// - EigenLayer restaking: Slashing cascades across multiple AVSs
/// - Shared validator sets between protocols
/// - Cross-chain validator coordination
/// - Collateral rehypothecation leading to cascade slashing
///
/// Risk: $50B+ in restaking protocols (EigenLayer, Symbiotic, Karak)

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractSlashingCascadeVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub cascade_type: CascadeType,
    pub amplification_factor: String,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CascadeType {
    /// Shared validator state across protocols
    SharedValidatorState,
    /// Rehypothecated collateral slashing
    RehypothecatedSlashing,
    /// Cross-protocol slashing coordination
    CoordinatedSlashing,
    /// Recursive slashing amplification
    RecursiveSlashing,
    /// Unprotected cross-protocol slashing trigger
    UnprotectedTrigger,
}

pub struct CrossContractSlashingCascadeAnalyzer;

impl CrossContractSlashingCascadeAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractSlashingCascadeVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_shared_validator_slashing(bytecode) {
            vulnerabilities.push(CrossContractSlashingCascadeVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Slashing event triggers cross-protocol validator penalties".to_string(),
                location: "Slashing logic".to_string(),
                cascade_type: CascadeType::SharedValidatorState,
                amplification_factor: "N protocols".to_string(),
                impact: "Single slashing event can cascade across all protocols using shared validators".to_string(),
            });
        }

        if self.has_rehypothecated_collateral_slashing(bytecode) {
            vulnerabilities.push(CrossContractSlashingCascadeVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Shared collateral slashing affects multiple protocols".to_string(),
                location: "Collateral management".to_string(),
                cascade_type: CascadeType::RehypothecatedSlashing,
                amplification_factor: "Collateral ratio multiplier".to_string(),
                impact: "Slashing in one protocol affects all protocols using same collateral".to_string(),
            });
        }

        if self.has_recursive_slashing(bytecode) {
            vulnerabilities.push(CrossContractSlashingCascadeVulnerability {
                severity: SecuritySeverity::High,
                description: "Slashing can trigger additional slashing in dependent protocols".to_string(),
                location: "Recursive slashing trigger".to_string(),
                cascade_type: CascadeType::RecursiveSlashing,
                amplification_factor: "Exponential".to_string(),
                impact: "Slashing amplifies through protocol dependencies".to_string(),
            });
        }

        if self.has_unprotected_cross_protocol_trigger(bytecode) {
            vulnerabilities.push(CrossContractSlashingCascadeVulnerability {
                severity: SecuritySeverity::High,
                description: "External protocol can trigger slashing without proper validation".to_string(),
                location: "External slashing trigger".to_string(),
                cascade_type: CascadeType::UnprotectedTrigger,
                amplification_factor: "Unbounded".to_string(),
                impact: "Malicious or compromised protocol can trigger mass slashing".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_shared_validator_slashing(&self, bytecode: &[u8]) -> bool {
        // Look for: external call for validator state + slashing logic
        let slash_sig = &[0x71, 0xd1, 0x48, 0x8b]; // slash(address) common signature
        
        bytecode.windows(4).any(|w| w == slash_sig) &&
        bytecode.windows(30).any(|window| {
            window.contains(&0xfa) && // STATICCALL (validator state query)
            window.contains(&0x55)    // SSTORE (apply slashing)
        })
    }

    fn has_rehypothecated_collateral_slashing(&self, bytecode: &[u8]) -> bool {
        // Look for: collateral balance query from external + slashing based on it
        bytecode.windows(50).any(|window| {
            window.contains(&0xfa) && // External collateral query
            window.contains(&0x04) && // DIV (calculate slash amount)
            window.contains(&0x55) && // SSTORE (apply slash)
            window.iter().filter(|&&op| op == 0xfa).count() >= 2 // Multiple external queries
        })
    }

    fn has_recursive_slashing(&self, bytecode: &[u8]) -> bool {
        // Look for: slashing that triggers external calls (potential cascade)
        bytecode.windows(40).any(|window| {
            window.contains(&0x55) && // SSTORE (slash state change)
            window.contains(&0xf1) && // CALL (trigger external)
            !window.contains(&0x57)   // No check to prevent recursion
        })
    }

    fn has_unprotected_cross_protocol_trigger(&self, bytecode: &[u8]) -> bool {
        // Look for: external-callable slash function without strong access control
        let slash_sig = &[0x71, 0xd1, 0x48, 0x8b];
        
        bytecode.windows(4).any(|w| w == slash_sig) &&
        !bytecode.windows(20).any(|window| {
            window.contains(&0x33) && // CALLER
            window.contains(&0x14) && // EQ
            window.contains(&0x57)    // JUMPI (access control)
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractSlashingCascadeVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractSlashingCascade,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!(
                "Cross-Contract Slashing Cascade: {} - Amplification: {} - Impact: {}",
                vuln.description, vuln.amplification_factor, vuln.impact
            ),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement cascade protection and independent slashing verification", vuln.location),
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_validator_slashing() {
        let analyzer = CrossContractSlashingCascadeAnalyzer::new();
        
        let bytecode = vec![
            0x71, 0xd1, 0x48, 0x8b, // slash() signature
            0xfa,                     // STATICCALL (validator query)
            0x55,                     // SSTORE (apply slash)
        ];
        
        let vulns = analyzer.analyze(&bytecode);
        assert!(!vulns.is_empty());
    }
}
