/// Cross-Contract Emergency Pause Desynchronization Detector
///
/// Detects vulnerabilities where emergency pauses in one protocol don't
/// properly synchronize with dependent protocols, creating risk windows.
///
/// Examples:
/// - Aave paused but integrated Yearn vaults continue operating
/// - Compound frozen market still affecting liquidation bots
/// - Emergency shutdown in one protocol not propagating to integrations
///
/// Risk: Cascade failures during emergency situations

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractEmergencyDesyncVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub desync_type: EmergencyDesyncType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EmergencyDesyncType {
    /// Pause in one protocol doesn't affect integrations
    PausePropagationFailure,
    /// Emergency actions not coordinated
    UncoordinatedEmergency,
    /// Recovery desynchronization
    RecoveryDesync,
    /// Partial pause vulnerability
    PartialPauseExploitation,
}

pub struct CrossContractEmergencyDesyncAnalyzer;

impl CrossContractEmergencyDesyncAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractEmergencyDesyncVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_pause_propagation_failure(bytecode) {
            vulnerabilities.push(CrossContractEmergencyDesyncVulnerability {
                severity: SecuritySeverity::High,
                description: "External protocol calls not checked against pause state".to_string(),
                location: "Pause enforcement".to_string(),
                desync_type: EmergencyDesyncType::PausePropagationFailure,
                impact: "Paused protocol can still be affected by unpaused integrations".to_string(),
            });
        }

        if self.has_uncoordinated_emergency(bytecode) {
            vulnerabilities.push(CrossContractEmergencyDesyncVulnerability {
                severity: SecuritySeverity::High,
                description: "Emergency functions don't coordinate with dependent protocols".to_string(),
                location: "Emergency handler".to_string(),
                desync_type: EmergencyDesyncType::UncoordinatedEmergency,
                impact: "Emergency actions create inconsistent state across protocols".to_string(),
            });
        }

        if self.has_partial_pause_exploitation(bytecode) {
            vulnerabilities.push(CrossContractEmergencyDesyncVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Partial pause allows exploitation through unpau sed paths".to_string(),
                location: "Pause granularity".to_string(),
                desync_type: EmergencyDesyncType::PartialPauseExploitation,
                impact: "Attackers can route through unpaused cross-protocol paths".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_pause_propagation_failure(&self, bytecode: &[u8]) -> bool {
        // Look for: external calls without pause state check
        bytecode.windows(40).any(|window| {
            window.contains(&0xf1) && // External CALL
            !window.contains(&0x54) && // No SLOAD (pause state check)
            !window.contains(&0x15)    // No ISZERO (pause check)
        })
    }

    fn has_uncoordinated_emergency(&self, bytecode: &[u8]) -> bool {
        // Look for: emergency function (likely contains revert/selfdestruct) without external coordination
        bytecode.windows(50).any(|window| {
            window.contains(&0xfd) && // REVERT (emergency)
            !window.contains(&0xf1) && // No external CALL
            window.contains(&0x55)    // SSTORE (state change without coordination)
        })
    }

    fn has_partial_pause_exploitation(&self, bytecode: &[u8]) -> bool {
        // Look for: multiple pause states or selective pausing
        let pause_checks = bytecode.windows(20).filter(|window| {
            window.contains(&0x54) && // SLOAD
            window.contains(&0x15)    // ISZERO (pause check)
        }).count();

        pause_checks >= 2 && // Multiple pause states
        bytecode.contains(&0xf1) // Has external calls
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractEmergencyDesyncVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractEmergencyDesync,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!(
                "Cross-Contract Emergency Desync: {} - Impact: {}",
                vuln.description, vuln.impact
            ),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement coordinated emergency mechanisms", vuln.location),
        }).collect()
    }
}
