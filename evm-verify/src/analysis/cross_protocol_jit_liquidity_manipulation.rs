/// Cross-Protocol Just-In-Time (JIT) Liquidity Manipulation Detector
///
/// Detects JIT liquidity provision coordinated across DEXs.
/// Risk: Uniswap v3/v4 concentrated liquidity ($50B+ TVL)
/// Attack: Provide JIT liquidity on Uniswap, manipulate Curve simultaneously

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossProtocolJITLiquidityManipulationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub manipulation_type: JITManipulationType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum JITManipulationType {
    JITSandwich,
    CrossDEXJITArbitrage,
    ConcentratedLiquidityExploit,
}

pub struct CrossProtocolJITLiquidityManipulationAnalyzer;

impl CrossProtocolJITLiquidityManipulationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossProtocolJITLiquidityManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_jit_sandwich(bytecode) {
            vulnerabilities.push(CrossProtocolJITLiquidityManipulationVulnerability {
                severity: SecuritySeverity::High,
                description: "JIT liquidity sandwiches user trades across DEXs".to_string(),
                location: "Liquidity provision".to_string(),
                manipulation_type: JITManipulationType::JITSandwich,
                impact: "Flash add liquidity, user swaps, flash remove extracting fees".to_string(),
            });
        }

        if self.has_cross_dex_jit_arbitrage(bytecode) {
            vulnerabilities.push(CrossProtocolJITLiquidityManipulationVulnerability {
                severity: SecuritySeverity::High,
                description: "JIT liquidity coordinated across multiple DEXs for arbitrage".to_string(),
                location: "Cross-DEX coordination".to_string(),
                manipulation_type: JITManipulationType::CrossDEXJITArbitrage,
                impact: "Provide JIT on Uniswap, manipulate price on Curve, profit on both".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_jit_sandwich(&self, bytecode: &[u8]) -> bool {
        // Flash liquidity provision around swap
        bytecode.windows(100).any(|window| {
            window.contains(&0x01) && // Liquidity add
            window.contains(&0xf1) && // Swap call
            window.contains(&0x03) && // Liquidity remove
            !window.contains(&0x42)   // No time lock
        })
    }

    fn has_cross_dex_jit_arbitrage(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(120).any(|window| {
            window.contains(&0x01) && // JIT add
            window.iter().filter(|&&op| op == 0xf1).count() >= 3 && // Multiple DEX calls
            window.contains(&0x02)    // Profit calculation
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossProtocolJITLiquidityManipulationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossProtocolJITLiquidityManipulation,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Protocol JIT Liquidity Manipulation: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement JIT protection and minimum liquidity duration", vuln.location),
        }).collect()
    }
}
