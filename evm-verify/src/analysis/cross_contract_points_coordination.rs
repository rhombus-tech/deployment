/// Cross-Contract Points/Incentive Coordination Detector
///
/// Detects coordinated farming across multiple points/incentive programs.
/// Risk: Points programs ($50B+ in restaking, DeFi incentives)

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractPointsCoordinationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub coordination_type: PointsCoordinationType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PointsCoordinationType {
    MultiProtocolPointsFarming,
    PointsArbitrage,
    CoordinatedIncentiveGaming,
    CrossProtocolRewardStacking,
}

pub struct CrossContractPointsCoordinationAnalyzer;

impl CrossContractPointsCoordinationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractPointsCoordinationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_multi_protocol_farming(bytecode) {
            vulnerabilities.push(CrossContractPointsCoordinationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Points can be farmed simultaneously across multiple protocols".to_string(),
                location: "Points accrual".to_string(),
                coordination_type: PointsCoordinationType::MultiProtocolPointsFarming,
                impact: "Sybil attacks and farming can drain incentive budgets".to_string(),
            });
        }

        if self.has_reward_stacking(bytecode) {
            vulnerabilities.push(CrossContractPointsCoordinationVulnerability {
                severity: SecuritySeverity::Low,
                description: "Rewards can be stacked across protocol integrations".to_string(),
                location: "Reward calculation".to_string(),
                coordination_type: PointsCoordinationType::CrossProtocolRewardStacking,
                impact: "Unintended reward multiplication through protocol composition".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_multi_protocol_farming(&self, bytecode: &[u8]) -> bool {
        // Look for: multiple external calls + reward accrual
        bytecode.windows(60).any(|window| {
            window.iter().filter(|&&op| op == 0xf1).count() >= 2 && // Multiple calls
            window.contains(&0x01) && // ADD (points accrual)
            window.contains(&0x55)    // SSTORE (save points)
        })
    }

    fn has_reward_stacking(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(50).any(|window| {
            window.contains(&0xfa) && // External reward query
            window.contains(&0x02) && // MUL (multiplier)
            window.contains(&0x01) && // ADD (stack)
            !window.contains(&0x11)   // No cap check
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractPointsCoordinationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractPointsCoordination,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Contract Points Coordination: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement Sybil resistance and reward caps", vuln.location),
        }).collect()
    }
}
