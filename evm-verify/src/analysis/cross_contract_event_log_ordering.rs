/// Cross-Contract Event Log Ordering Exploitation Detector
///
/// Detects event ordering inconsistencies breaking cross-contract logic.
/// Risk: All event-driven integrations
/// Attack: Events processed in wrong order across protocols

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractEventLogOrderingVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub ordering_issue: EventOrderingIssue,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EventOrderingIssue {
    CrossProtocolEventRace,
    EventProcessingDesync,
    DependentEventMisordering,
}

pub struct CrossContractEventLogOrderingAnalyzer;

impl CrossContractEventLogOrderingAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractEventLogOrderingVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_cross_protocol_event_race(bytecode) {
            vulnerabilities.push(CrossContractEventLogOrderingVulnerability {
                severity: SecuritySeverity::High,
                description: "Events emitted in different order across protocols".to_string(),
                location: "Event emission".to_string(),
                ordering_issue: EventOrderingIssue::CrossProtocolEventRace,
                impact: "Transfer event before Approval breaks integrations".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_cross_protocol_event_race(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(80).any(|window| {
            window.iter().filter(|&&op| op == 0xa0).count() >= 2 && // Multiple LOG0 (events)
            window.contains(&0xf1) && // Cross-protocol
            !window.contains(&0x54)   // No ordering guarantee
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractEventLogOrderingVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractEventLogOrdering,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Contract Event Log Ordering: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement event ordering guarantees and dependencies", vuln.location),
        }).collect()
    }
}
