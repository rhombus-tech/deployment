/// Cross-Contract Insurance Pool Drain Detector
///
/// Detects vulnerabilities where shared insurance pools can be drained
/// through coordinated attacks across multiple protocols.
///
/// Examples:
/// - Rari/Fuse: Shared insurance pool exploitation
/// - Compound/Aave insurance coordination attacks
/// - Cross-protocol bad debt socialization
///
/// Risk: Insurance protocols ($5B+ TVL in Nexus Mutual, Unslashed, etc.)

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractInsurancePoolDrainVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub drain_vector: InsuranceDrainVector,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InsuranceDrainVector {
    /// Shared pool across multiple protocols
    SharedPoolExploitation,
    /// Bad debt socialization cascade
    BadDebtSocialization,
    /// Insurance claim coordination
    CoordinatedClaims,
    /// Reserve depletion through cross-protocol losses
    ReserveDepletion,
    /// Coverage limit bypass via multiple protocols
    CoverageLimitBypass,
}

pub struct CrossContractInsurancePoolDrainAnalyzer;

impl CrossContractInsurancePoolDrainAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractInsurancePoolDrainVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_shared_pool_exploitation(bytecode) {
            vulnerabilities.push(CrossContractInsurancePoolDrainVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Insurance pool shared across protocols without isolation".to_string(),
                location: "Pool management".to_string(),
                drain_vector: InsuranceDrainVector::SharedPoolExploitation,
                impact: "Loss in one protocol drains insurance for all protocols".to_string(),
            });
        }

        if self.has_bad_debt_socialization(bytecode) {
            vulnerabilities.push(CrossContractInsurancePoolDrainVulnerability {
                severity: SecuritySeverity::High,
                description: "Bad debt from external protocols socialized to insurance pool".to_string(),
                location: "Debt settlement".to_string(),
                drain_vector: InsuranceDrainVector::BadDebtSocialization,
                impact: "Unlimited bad debt can exhaust insurance reserves".to_string(),
            });
        }

        if self.has_coordinated_claims(bytecode) {
            vulnerabilities.push(CrossContractInsurancePoolDrainVulnerability {
                severity: SecuritySeverity::High,
                description: "Multiple protocols can claim insurance simultaneously".to_string(),
                location: "Claim processing".to_string(),
                drain_vector: InsuranceDrainVector::CoordinatedClaims,
                impact: "Coordinated claims can exceed pool capacity".to_string(),
            });
        }

        if self.has_coverage_limit_bypass(bytecode) {
            vulnerabilities.push(CrossContractInsurancePoolDrainVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Coverage limits can be bypassed through multiple protocol integrations".to_string(),
                location: "Coverage calculation".to_string(),
                drain_vector: InsuranceDrainVector::CoverageLimitBypass,
                impact: "Effective coverage exceeds intended limits".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_shared_pool_exploitation(&self, bytecode: &[u8]) -> bool {
        // Look for: insurance pool access from multiple sources
        bytecode.windows(50).any(|window| {
            window.contains(&0x54) && // SLOAD (pool balance)
            window.contains(&0x03) && // SUB (decrease)
            window.contains(&0xf1) && // External call
            !window.contains(&0x33)   // No CALLER restriction
        })
    }

    fn has_bad_debt_socialization(&self, bytecode: &[u8]) -> bool {
        // Look for: external debt added to internal pool
        bytecode.windows(50).any(|window| {
            window.contains(&0xfa) && // STATICCALL (external debt)
            window.contains(&0x01) && // ADD (to pool)
            window.contains(&0x55) && // SSTORE (update pool)
            !window.contains(&0x11)   // No GT (no cap check)
        })
    }

    fn has_coordinated_claims(&self, bytecode: &[u8]) -> bool {
        // Look for: claim function without global limit check
        let claim_sig = &[0x4e, 0x71, 0xd9, 0x2d]; // claim()
        
        bytecode.windows(4).any(|w| w == claim_sig) &&
        !bytecode.windows(30).any(|window| {
            // No global pool check before claim
            window.contains(&0x54) && // SLOAD
            window.contains(&0x10) && // LT
            window.contains(&0x57)    // JUMPI (revert if insufficient)
        })
    }

    fn has_coverage_limit_bypass(&self, bytecode: &[u8]) -> bool {
        // Look for: coverage calculation without aggregation across protocols
        bytecode.windows(50).any(|window| {
            window.contains(&0x02) && // MUL (coverage calc)
            !window.contains(&0xfa) && // No external coverage query
            window.contains(&0x55)    // SSTORE (set coverage)
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractInsurancePoolDrainVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractInsurancePoolDrain,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!(
                "Cross-Contract Insurance Pool Drain: {} - Impact: {}",
                vuln.description, vuln.impact
            ),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement pool isolation and coverage caps", vuln.location),
        }).collect()
    }
}
