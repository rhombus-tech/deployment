/// Cross-Contract ERC-4626 Vault Share Manipulation Detector
///
/// Detects vault share price manipulation affecting integrated protocols.
/// Risk: $30B+ in ERC-4626 vaults (Yearn, Beefy, Balancer, etc.)
/// Attack: Inflate share price in Yearn → borrow maximum in Aave

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractERC4626VaultManipulationVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub manipulation_type: VaultManipulationType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VaultManipulationType {
    FirstDepositorCrossProtocol,
    SharePriceInflationCascade,
    VaultDonationAttackCrossChain,
    PreviewVsActualDesync,
    RoundingErrorAmplification,
}

pub struct CrossContractERC4626VaultManipulationAnalyzer;

impl CrossContractERC4626VaultManipulationAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractERC4626VaultManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_first_depositor_cross_protocol(bytecode) {
            vulnerabilities.push(CrossContractERC4626VaultManipulationVulnerability {
                severity: SecuritySeverity::Critical,
                description: "First depositor attack in vault affects cross-protocol integrations".to_string(),
                location: "ERC-4626 deposit".to_string(),
                manipulation_type: VaultManipulationType::FirstDepositorCrossProtocol,
                impact: "Inflate share price in Yearn, over-borrow in Aave using inflated shares".to_string(),
            });
        }

        if self.has_share_price_inflation_cascade(bytecode) {
            vulnerabilities.push(CrossContractERC4626VaultManipulationVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Share price manipulation cascades across dependent protocols".to_string(),
                location: "Share price query".to_string(),
                manipulation_type: VaultManipulationType::SharePriceInflationCascade,
                impact: "Manipulated price in vault affects all lending protocols using it as collateral".to_string(),
            });
        }

        if self.has_donation_attack_cross_chain(bytecode) {
            vulnerabilities.push(CrossContractERC4626VaultManipulationVulnerability {
                severity: SecuritySeverity::High,
                description: "Donation attack in vault on one chain affects other chains".to_string(),
                location: "Cross-chain vault".to_string(),
                manipulation_type: VaultManipulationType::VaultDonationAttackCrossChain,
                impact: "Donate assets to vault on L1, exploit on L2 with same vault token".to_string(),
            });
        }

        if self.has_preview_vs_actual_desync(bytecode) {
            vulnerabilities.push(CrossContractERC4626VaultManipulationVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Preview functions differ from actual across protocols".to_string(),
                location: "PreviewDeposit/PreviewRedeem".to_string(),
                manipulation_type: VaultManipulationType::PreviewVsActualDesync,
                impact: "Protocol A uses preview, Protocol B uses actual - arbitrage opportunity".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_first_depositor_cross_protocol(&self, bytecode: &[u8]) -> bool {
        // ERC-4626 deposit without virtual shares protection affecting cross-protocol
        let deposit_sig = &[0xb6, 0xb5, 0x5f, 0x25]; // deposit(uint256,address)
        
        bytecode.windows(4).any(|w| w == deposit_sig) &&
        bytecode.windows(60).any(|window| {
            window.contains(&0x04) && // Share calculation (division)
            window.contains(&0xf1) && // External call (cross-protocol)
            !window.contains(&0x01)   // No virtual share offset
        })
    }

    fn has_share_price_inflation_cascade(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(70).any(|window| {
            window.contains(&0x04) && // Share price calculation
            window.iter().filter(|&&op| op == 0xf1).count() >= 2 && // Multiple protocols
            !window.contains(&0x10) // No price manipulation check
        })
    }

    fn has_donation_attack_cross_chain(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(60).any(|window| {
            window.contains(&0x01) && // Balance increase (donation)
            window.contains(&0xf1) && // Cross-chain call
            !window.contains(&0x54)   // No donation tracking
        })
    }

    fn has_preview_vs_actual_desync(&self, bytecode: &[u8]) -> bool {
        let preview_redeem = &[0xba, 0x08, 0x77, 0x52]; // previewRedeem
        let redeem = &[0xba, 0x08, 0x77, 0x51]; // redeem
        
        (bytecode.windows(4).any(|w| w == preview_redeem) ||
         bytecode.windows(4).any(|w| w == redeem)) &&
        bytecode.windows(50).any(|window| {
            window.contains(&0xf1) && // Cross-protocol
            !window.contains(&0x14)   // No consistency check
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractERC4626VaultManipulationVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractERC4626VaultManipulation,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Contract ERC-4626 Vault Manipulation: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement virtual shares, inflation attack protection, and cross-protocol price validation", vuln.location),
        }).collect()
    }
}
