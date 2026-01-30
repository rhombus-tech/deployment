/// Cross-Protocol Flash Accounting Window Detector
///
/// Detects intra-block state inconsistencies across integrated protocols.
/// Risk: All flash loan integrations
/// Attack: Flash mint in Protocol A, exploit accounting window in Protocol B

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossProtocolFlashAccountingWindowVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub accounting_issue: FlashAccountingIssue,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FlashAccountingIssue {
    IntraBlockStateDesync,
    FlashMintAccountingGap,
    AtomicSupplyManipulation,
    CrossProtocolFlashArbitrage,
    AccountingSnapshotRace,
}

pub struct CrossProtocolFlashAccountingWindowAnalyzer;

impl CrossProtocolFlashAccountingWindowAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossProtocolFlashAccountingWindowVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_intra_block_state_desync(bytecode) {
            vulnerabilities.push(CrossProtocolFlashAccountingWindowVulnerability {
                severity: SecuritySeverity::Critical,
                description: "State changes visible to Protocol B before Protocol A completes".to_string(),
                location: "Intra-block state".to_string(),
                accounting_issue: FlashAccountingIssue::IntraBlockStateDesync,
                impact: "Flash loan in A visible in B's accounting before A's state finalized".to_string(),
            });
        }

        if self.has_flash_mint_accounting_gap(bytecode) {
            vulnerabilities.push(CrossProtocolFlashAccountingWindowVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Flash mint creates accounting window exploitable by other protocols".to_string(),
                location: "Flash mint".to_string(),
                accounting_issue: FlashAccountingIssue::FlashMintAccountingGap,
                impact: "Flash mint 1M tokens, Protocol B sees increased supply, exploit before burn".to_string(),
            });
        }

        if self.has_atomic_supply_manipulation(bytecode) {
            vulnerabilities.push(CrossProtocolFlashAccountingWindowVulnerability {
                severity: SecuritySeverity::High,
                description: "Token supply manipulated within same transaction across protocols".to_string(),
                location: "Supply calculation".to_string(),
                accounting_issue: FlashAccountingIssue::AtomicSupplyManipulation,
                impact: "Inflate supply in Protocol A, exploit in Protocol B, deflate before end".to_string(),
            });
        }

        if self.has_accounting_snapshot_race(bytecode) {
            vulnerabilities.push(CrossProtocolFlashAccountingWindowVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Accounting snapshots taken at different points in transaction".to_string(),
                location: "Snapshot timing".to_string(),
                accounting_issue: FlashAccountingIssue::AccountingSnapshotRace,
                impact: "Protocol A snapshots before manipulation, Protocol B after".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_intra_block_state_desync(&self, bytecode: &[u8]) -> bool {
        // State change visible before transaction completes
        bytecode.windows(70).any(|window| {
            window.contains(&0x55) && // State write
            window.contains(&0xf1) && // External call (can query state)
            !window.contains(&0x57) && // No revert on failure
            window.contains(&0x54)     // State read after write
        })
    }

    fn has_flash_mint_accounting_gap(&self, bytecode: &[u8]) -> bool {
        // Flash mint without immediate accounting update
        bytecode.windows(80).any(|window| {
            window.contains(&0x01) && // Balance increase (mint)
            window.contains(&0xf1) && // External call
            !window.contains(&0x55) && // No supply tracking update
            window.contains(&0x03)     // Later burn
        })
    }

    fn has_atomic_supply_manipulation(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(90).any(|window| {
            window.contains(&0x01) && // Supply increase
            window.iter().filter(|&&op| op == 0xf1).count() >= 2 && // Multi-protocol
            window.contains(&0x03) && // Supply decrease
            !window.contains(&0x54)   // No supply snapshot protection
        })
    }

    fn has_accounting_snapshot_race(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(60).any(|window| {
            window.contains(&0x54) && // Snapshot (SLOAD)
            window.contains(&0x55) && // State change
            window.contains(&0xf1) && // External query
            !window.contains(&0x42)   // No timestamp consistency
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossProtocolFlashAccountingWindowVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossProtocolFlashAccountingWindow,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Protocol Flash Accounting Window: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement atomic accounting updates and state consistency checks", vuln.location),
        }).collect()
    }
}
