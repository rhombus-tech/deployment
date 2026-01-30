/// Cross-Protocol Vesting Schedule Manipulation Detector
///
/// Detects vesting schedule gaming across integrated protocols.
/// Risk: Token launches, DAO compensation, investor vesting
/// Attack: Use unvested tokens as collateral before unlock

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossProtocolVestingScheduleManipulationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub manipulation_type: VestingManipulationType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VestingManipulationType {
    UnvestedAsCollateral,
    VestingScheduleDesync,
    CliffBypass,
    AcceleratedVesting,
}

pub struct CrossProtocolVestingScheduleManipulationAnalyzer;

impl CrossProtocolVestingScheduleManipulationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossProtocolVestingScheduleManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_unvested_as_collateral(bytecode) {
            vulnerabilities.push(CrossProtocolVestingScheduleManipulationVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Unvested tokens used as collateral in other protocols".to_string(),
                location: "Vesting verification".to_string(),
                manipulation_type: VestingManipulationType::UnvestedAsCollateral,
                impact: "$10M unvested tokens used for $5M loan before unlock".to_string(),
            });
        }

        if self.has_vesting_schedule_desync(bytecode) {
            vulnerabilities.push(CrossProtocolVestingScheduleManipulationVulnerability {
                severity: SecuritySeverity::High,
                description: "Vesting schedule differs across protocols".to_string(),
                location: "Schedule synchronization".to_string(),
                manipulation_type: VestingManipulationType::VestingScheduleDesync,
                impact: "Protocol A shows vested, Protocol B shows unvested".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_unvested_as_collateral(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(60).any(|window| {
            window.contains(&0x31) && // Balance query
            window.contains(&0xf1) && // Cross-protocol use
            !window.contains(&0x42) && // No vesting time check
            !window.contains(&0x54)    // No vested amount verification
        })
    }

    fn has_vesting_schedule_desync(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(70).any(|window| {
            window.contains(&0x42) && // Timestamp (vesting)
            window.iter().filter(|&&op| op == 0xf1).count() >= 2 && // Multi-protocol
            !window.contains(&0x14) // No schedule consistency check
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossProtocolVestingScheduleManipulationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossProtocolVestingScheduleManipulation,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Protocol Vesting Schedule Manipulation: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement vesting verification before cross-protocol usage", vuln.location),
        }).collect()
    }
}
