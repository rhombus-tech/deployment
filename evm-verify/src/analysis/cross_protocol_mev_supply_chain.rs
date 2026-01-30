/// Cross-Protocol MEV Supply Chain Exploitation Detector
///
/// Detects coordinated MEV extraction across entire supply chain.
/// Risk: Searchers → Builders → Validators → Protocols ($1B+ annual MEV)
/// Attack: Full supply chain coordination for maximum extraction

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossProtocolMEVSupplyChainVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub supply_chain_risk: MEVSupplyChainRisk,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MEVSupplyChainRisk {
    SearcherBuilderCollusion,
    BuilderValidatorCoordination,
    VerticalIntegrationExploit,
    SupplyChainCensorship,
}

pub struct CrossProtocolMEVSupplyChainAnalyzer;

impl CrossProtocolMEVSupplyChainAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossProtocolMEVSupplyChainVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_searcher_builder_collusion(bytecode) {
            vulnerabilities.push(CrossProtocolMEVSupplyChainVulnerability {
                severity: SecuritySeverity::High,
                description: "Searcher and builder coordinate MEV extraction across protocols".to_string(),
                location: "MEV supply chain".to_string(),
                supply_chain_risk: MEVSupplyChainRisk::SearcherBuilderCollusion,
                impact: "Builder frontru

ns Protocol A knowing searcher will backrun Protocol B".to_string(),
            });
        }

        if self.has_builder_validator_coordination(bytecode) {
            vulnerabilities.push(CrossProtocolMEVSupplyChainVulnerability {
                severity: SecuritySeverity::High,
                description: "Builder coordinates with validator for cross-protocol MEV".to_string(),
                location: "Block building".to_string(),
                supply_chain_risk: MEVSupplyChainRisk::BuilderValidatorCoordination,
                impact: "Validator includes specific transactions enabling builder's cross-protocol MEV".to_string(),
            });
        }

        if self.has_vertical_integration_exploit(bytecode) {
            vulnerabilities.push(CrossProtocolMEVSupplyChainVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Vertically integrated entity controls multiple supply chain layers".to_string(),
                location: "Supply chain integration".to_string(),
                supply_chain_risk: MEVSupplyChainRisk::VerticalIntegrationExploit,
                impact: "Same entity is searcher + builder + validator extracting maximum MEV".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_searcher_builder_collusion(&self, bytecode: &[u8]) -> bool {
        // Multi-protocol MEV without fair ordering
        bytecode.windows(100).any(|window| {
            window.iter().filter(|&&op| op == 0xf1).count() >= 3 && // Multiple protocols
            window.contains(&0x02) && // Profit calculation
            !window.contains(&0x20) && // No commitment scheme
            !window.contains(&0x42)    // No time-lock
        })
    }

    fn has_builder_validator_coordination(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(80).any(|window| {
            window.contains(&0x43) && // Block number dependency
            window.iter().filter(|&&op| op == 0xf1).count() >= 2 && // Multi-protocol
            !window.contains(&0x54)   // No inclusion proof
        })
    }

    fn has_vertical_integration_exploit(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(120).any(|window| {
            window.iter().filter(|&&op| op == 0xf1).count() >= 4 && // Extensive cross-protocol
            window.contains(&0x33) && // Beneficiary address (same entity)
            !window.contains(&0x14)   // No separation verification
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossProtocolMEVSupplyChainVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossProtocolMEVSupplyChain,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Protocol MEV Supply Chain: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Use private mempools, commit-reveal schemes, or time-delayed execution", vuln.location),
        }).collect()
    }
}
