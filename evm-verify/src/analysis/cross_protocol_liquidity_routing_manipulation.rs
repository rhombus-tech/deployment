/// Cross-Protocol Liquidity Routing Manipulation Detector
///
/// Detects optimal routing manipulation across DEX aggregators.
/// Risk: 1inch, CoW Protocol, Matcha, ParaSwap ($10B+ aggregated volume)
/// Attack: Suboptimal routing extracts slippage and fees

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossProtocolLiquidityRoutingManipulationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub routing_manipulation: RoutingManipulationType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RoutingManipulationType {
    SuboptimalRouting,
    RoutingGraphPoisoning,
    LiquidityFragmentationExploit,
    GasOptimizationBypass,
}

pub struct CrossProtocolLiquidityRoutingManipulationAnalyzer;

impl CrossProtocolLiquidityRoutingManipulationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossProtocolLiquidityRoutingManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_suboptimal_routing(bytecode) {
            vulnerabilities.push(CrossProtocolLiquidityRoutingManipulationVulnerability {
                severity: SecuritySeverity::High,
                description: "Routing algorithm selects suboptimal path extracting value".to_string(),
                location: "Route selection".to_string(),
                routing_manipulation: RoutingManipulationType::SuboptimalRouting,
                impact: "$10M trade routed through low-liquidity pools extracting $100K slippage".to_string(),
            });
        }

        if self.has_routing_graph_poisoning(bytecode) {
            vulnerabilities.push(CrossProtocolLiquidityRoutingManipulationVulnerability {
                severity: SecuritySeverity::High,
                description: "Routing graph manipulated to favor specific pools".to_string(),
                location: "Graph construction".to_string(),
                routing_manipulation: RoutingManipulationType::RoutingGraphPoisoning,
                impact: "Aggregator routes all trades through attacker's controlled pool".to_string(),
            });
        }

        if self.has_liquidity_fragmentation_exploit(bytecode) {
            vulnerabilities.push(CrossProtocolLiquidityRoutingManipulationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Routing splits trade across many pools increasing gas/slippage".to_string(),
                location: "Split routing".to_string(),
                routing_manipulation: RoutingManipulationType::LiquidityFragmentationExploit,
                impact: "Trade fragmented into 10 hops each taking fees".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_suboptimal_routing(&self, bytecode: &[u8]) -> bool {
        // Route selection without optimal path verification
        bytecode.windows(80).any(|window| {
            window.iter().filter(|&&op| op == 0xf1).count() >= 2 && // Multiple DEX calls
            !window.contains(&0x10) && // No price comparison
            !window.contains(&0x04)    // No optimal ratio calculation
        })
    }

    fn has_routing_graph_poisoning(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(70).any(|window| {
            window.contains(&0x54) && // Graph/route data
            window.contains(&0xf1) && // External route selection
            !window.contains(&0x14) && // No validation
            !window.contains(&0x11)    // No bounds check
        })
    }

    fn has_liquidity_fragmentation_exploit(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(100).any(|window| {
            window.iter().filter(|&&op| op == 0xf1).count() >= 4 && // 4+ hops
            !window.contains(&0x5a) && // No gas cost calculation
            !window.contains(&0x10)    // No efficiency threshold
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossProtocolLiquidityRoutingManipulationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossProtocolLiquidityRoutingManipulation,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Protocol Liquidity Routing Manipulation: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement routing optimization verification and maximum hop limits", vuln.location),
        }).collect()
    }
}
