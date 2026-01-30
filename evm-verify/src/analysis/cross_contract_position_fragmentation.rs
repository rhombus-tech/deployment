/// Cross-Contract Position Fragmentation Detector
///
/// Detects vulnerabilities where single logical positions split across
/// multiple protocols create coordination and risk management failures.
///
/// Examples:
/// - LP position in Uniswap + separate yield farming in other protocol
/// - Collateral in Aave + leveraged position in dYdX
/// - NFT in lending protocol + same NFT wrapper in another protocol
///
/// Risk: Position management protocols, multi-protocol strategies

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractPositionFragmentationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub fragmentation_type: PositionFragmentationType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PositionFragmentationType {
    /// LP position split across protocols
    LPPositionFragmentation,
    /// Collateral in multiple protocols
    CollateralFragmentation,
    /// Orphaned position after partial liquidation
    OrphanedPosition,
    /// Uncoordinated position management
    UncoordinatedManagement,
    /// Cross-protocol position correlation
    PositionCorrelationRisk,
}

pub struct CrossContractPositionFragmentationAnalyzer;

impl CrossContractPositionFragmentationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractPositionFragmentationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_lp_position_fragmentation(bytecode) {
            vulnerabilities.push(CrossContractPositionFragmentationVulnerability {
                severity: SecuritySeverity::High,
                description: "LP position managed across multiple protocols without coordination".to_string(),
                location: "LP position management".to_string(),
                fragmentation_type: PositionFragmentationType::LPPositionFragmentation,
                impact: "Partial liquidation in one protocol orphans position in another".to_string(),
            });
        }

        if self.has_collateral_fragmentation(bytecode) {
            vulnerabilities.push(CrossContractPositionFragmentationVulnerability {
                severity: SecuritySeverity::High,
                description: "Collateral tracked separately across protocols".to_string(),
                location: "Collateral tracking".to_string(),
                fragmentation_type: PositionFragmentationType::CollateralFragmentation,
                impact: "Total exposure not visible, enabling over-leveraging".to_string(),
            });
        }

        if self.has_orphaned_position_risk(bytecode) {
            vulnerabilities.push(CrossContractPositionFragmentationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Liquidation in one protocol doesn't close positions in others".to_string(),
                location: "Liquidation logic".to_string(),
                fragmentation_type: PositionFragmentationType::OrphanedPosition,
                impact: "Partial liquidation leaves orphaned positions creating further risk".to_string(),
            });
        }

        if self.has_uncoordinated_management(bytecode) {
            vulnerabilities.push(CrossContractPositionFragmentationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Position updates not synchronized across protocols".to_string(),
                location: "Position update".to_string(),
                fragmentation_type: PositionFragmentationType::UncoordinatedManagement,
                impact: "Stale position data in one protocol while updated in another".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_lp_position_fragmentation(&self, bytecode: &[u8]) -> bool {
        // Look for: LP token operations + external protocol interaction
        let lp_sigs = [
            &[0x02, 0x5e, 0x7c, 0x27][..], // mint() - LP minting
            &[0x89, 0xaf, 0xca, 0xb3][..], // burn() - LP burning
        ];

        lp_sigs.iter().any(|sig| {
            bytecode.windows(sig.len()).any(|w| w == *sig)
        }) && bytecode.windows(50).any(|window| {
            window.contains(&0xf1) && // External call
            !window.contains(&0x14)   // No coordination check
        })
    }

    fn has_collateral_fragmentation(&self, bytecode: &[u8]) -> bool {
        // Look for: collateral deposit without global position tracking
        bytecode.windows(60).any(|window| {
            window.contains(&0x55) && // SSTORE (local collateral)
            window.contains(&0xf1) && // External call (to another protocol)
            !window.contains(&0xfa) && // No external position query
            window.iter().filter(|&&op| op == 0x02).count() >= 2 // Multiple value calculations
        })
    }

    fn has_orphaned_position_risk(&self, bytecode: &[u8]) -> bool {
        // Look for: liquidation without external position cleanup
        bytecode.windows(50).any(|window| {
            window.contains(&0x55) && // SSTORE (liquidation state)
            window.contains(&0x03) && // SUB (remove collateral)
            !window.contains(&0xf1)   // No external call to close related positions
        })
    }

    fn has_uncoordinated_management(&self, bytecode: &[u8]) -> bool {
        // Look for: position updates without cross-protocol sync
        bytecode.windows(50).any(|window| {
            window.contains(&0x01) && // ADD (position increase)
            window.contains(&0x55) && // SSTORE (save position)
            window.contains(&0xfa) && // External query
            !window.contains(&0x14)   // No sync verification
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractPositionFragmentationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractPositionFragmentation,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!(
                "Cross-Contract Position Fragmentation: {} - Impact: {}",
                vuln.description, vuln.impact
            ),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement coordinated position management", vuln.location),
        }).collect()
    }
}
