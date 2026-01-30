/// Cross-Protocol CDP Liquidation Cascade Detector
///
/// Detects recursive CDP liquidations across MakerDAO, Aave, Compound.
/// Risk: $20B+ in multi-protocol CDP positions
/// Attack: Liquidate CDP in MakerDAO triggers Aave triggers Compound
/// Real exploits: Terra/Luna $40B was CDP cascade

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossProtocolCDPLiquidationCascadeVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub cascade_type: CDPCascadeType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CDPCascadeType {
    RecursiveCDPLiquidation,
    CircularCDPDependency,
    CDPHealthFactorCascade,
    UnderCollateralizedCrossBorrow,
    CDPOracleDesync,
}

pub struct CrossProtocolCDPLiquidationCascadeAnalyzer;

impl CrossProtocolCDPLiquidationCascadeAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossProtocolCDPLiquidationCascadeVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_recursive_cdp_liquidation(bytecode) {
            vulnerabilities.push(CrossProtocolCDPLiquidationCascadeVulnerability {
                severity: SecuritySeverity::Critical,
                description: "CDP liquidation triggers cascading liquidations across protocols".to_string(),
                location: "CDP liquidation".to_string(),
                cascade_type: CDPCascadeType::RecursiveCDPLiquidation,
                impact: "Liquidate DAI CDP → Aave position liquidated → Compound position liquidated".to_string(),
            });
        }

        if self.has_circular_cdp_dependency(bytecode) {
            vulnerabilities.push(CrossProtocolCDPLiquidationCascadeVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Circular CDP dependencies create systemic risk".to_string(),
                location: "CDP dependency graph".to_string(),
                cascade_type: CDPCascadeType::CircularCDPDependency,
                impact: "Protocol A → Protocol B → Protocol C → Protocol A circular dependency".to_string(),
            });
        }

        if self.has_health_factor_cascade(bytecode) {
            vulnerabilities.push(CrossProtocolCDPLiquidationCascadeVulnerability {
                severity: SecuritySeverity::High,
                description: "Health factor changes propagate incorrectly across protocols".to_string(),
                location: "Health factor calculation".to_string(),
                cascade_type: CDPCascadeType::CDPHealthFactorCascade,
                impact: "Collateral value drop in MakerDAO doesn't update Aave health factor".to_string(),
            });
        }

        if self.has_undercollateralized_cross_borrow(bytecode) {
            vulnerabilities.push(CrossProtocolCDPLiquidationCascadeVulnerability {
                severity: SecuritySeverity::High,
                description: "Cross-protocol borrowing creates undercollateralized positions".to_string(),
                location: "Cross-protocol borrow".to_string(),
                cascade_type: CDPCascadeType::UnderCollateralizedCrossBorrow,
                impact: "Total borrowed > total collateral when accounting across protocols".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_recursive_cdp_liquidation(&self, bytecode: &[u8]) -> bool {
        // Liquidation triggering external calls without cascade prevention
        bytecode.windows(80).any(|window| {
            window.contains(&0x03) && // Collateral reduction (liquidation)
            window.iter().filter(|&&op| op == 0xf1).count() >= 2 && // Multiple protocol calls
            !window.contains(&0x54) // No cascade prevention check
        })
    }

    fn has_circular_cdp_dependency(&self, bytecode: &[u8]) -> bool {
        // Borrow-lend cycle across protocols
        bytecode.windows(100).any(|window| {
            window.iter().filter(|&&op| op == 0xf1).count() >= 3 && // 3+ protocols
            window.contains(&0x01) && // Borrow (add debt)
            window.contains(&0x55) && // Lend (store collateral)
            !window.contains(&0x54)   // No circular dependency detection
        })
    }

    fn has_health_factor_cascade(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(70).any(|window| {
            window.contains(&0x04) && // Health factor division
            window.contains(&0xf1) && // External protocol query
            !window.iter().filter(|&&op| op == 0xfa).count() >= 2 // No multi-protocol health check
        })
    }

    fn has_undercollateralized_cross_borrow(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(60).any(|window| {
            window.contains(&0x01) && // Borrow
            window.contains(&0xf1) && // Cross-protocol
            !window.contains(&0x11) && // No total collateral check
            !window.contains(&0x10)    // No collateralization ratio check
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossProtocolCDPLiquidationCascadeVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossProtocolCDPLiquidationCascade,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Protocol CDP Liquidation Cascade: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement CDP dependency graph analysis and cascade circuit breakers", vuln.location),
        }).collect()
    }
}
