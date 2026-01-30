/// Cross-Contract Accounting Mismatch Detector
///
/// Detects vulnerabilities where different accounting methods between protocols
/// create exploitable discrepancies (beyond just fee-on-transfer tokens).
///
/// Examples:
/// - Share-based vs balance-based accounting mismatches
/// - Rebasing token accounting errors
/// - Decimal precision mismatches
/// - Rounding direction conflicts
/// - Cumulative accounting errors
///
/// Real exploits: Rari Capital ($80M), Harvest ($24M), Indexed Finance ($16M)

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractAccountingMismatchVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub mismatch_type: MismatchType,
    pub protocols_affected: Vec<String>,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MismatchType {
    /// Share-based vs balance-based accounting
    ShareBalanceMismatch,
    /// Rebasing token accounting errors
    RebasingAccountingError,
    /// Decimal precision mismatches (18 vs 6 decimals)
    DecimalMismatch,
    /// Rounding direction conflicts (up vs down)
    RoundingDirectionConflict,
    /// Cumulative rounding error exploitation
    CumulativeRoundingError,
    /// Internal vs external balance discrepancy
    InternalExternalMismatch,
}

pub struct CrossContractAccountingMismatchAnalyzer;

impl CrossContractAccountingMismatchAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractAccountingMismatchVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_share_balance_mismatch(bytecode) {
            vulnerabilities.push(CrossContractAccountingMismatchVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Mixing share-based and balance-based accounting across protocols".to_string(),
                location: "Cross-protocol accounting".to_string(),
                mismatch_type: MismatchType::ShareBalanceMismatch,
                protocols_affected: vec!["Vault protocol".to_string(), "Pool protocol".to_string()],
                impact: "Share inflation/deflation can drain funds from protocols using different accounting".to_string(),
            });
        }

        if self.has_rebasing_accounting_error(bytecode) {
            vulnerabilities.push(CrossContractAccountingMismatchVulnerability {
                severity: SecuritySeverity::High,
                description: "Rebasing token balance changes not accounted for in cross-protocol transfers".to_string(),
                location: "Rebasing token handling".to_string(),
                mismatch_type: MismatchType::RebasingAccountingError,
                protocols_affected: vec!["Rebasing token protocol".to_string()],
                impact: "Positive/negative rebases can create accounting discrepancies".to_string(),
            });
        }

        if self.has_decimal_mismatch(bytecode) {
            vulnerabilities.push(CrossContractAccountingMismatchVulnerability {
                severity: SecuritySeverity::High,
                description: "Token decimal mismatches between protocols (e.g., 18 vs 6 decimals)".to_string(),
                location: "Decimal conversion".to_string(),
                mismatch_type: MismatchType::DecimalMismatch,
                protocols_affected: vec!["USDC (6 decimals)".to_string(), "WETH (18 decimals)".to_string()],
                impact: "Precision loss or overflow in cross-protocol calculations".to_string(),
            });
        }

        if self.has_rounding_direction_conflict(bytecode) {
            vulnerabilities.push(CrossContractAccountingMismatchVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Inconsistent rounding directions between protocols".to_string(),
                location: "Division/rounding logic".to_string(),
                mismatch_type: MismatchType::RoundingDirectionConflict,
                protocols_affected: vec!["Multiple protocols".to_string()],
                impact: "Systematic extraction of rounding differences".to_string(),
            });
        }

        if self.has_cumulative_rounding_error(bytecode) {
            vulnerabilities.push(CrossContractAccountingMismatchVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Cumulative rounding errors exploitable across protocols".to_string(),
                location: "Repeated divisions".to_string(),
                mismatch_type: MismatchType::CumulativeRoundingError,
                protocols_affected: vec!["Multiple protocols".to_string()],
                impact: "Many small roundings accumulate to significant loss".to_string(),
            });
        }

        if self.has_internal_external_mismatch(bytecode) {
            vulnerabilities.push(CrossContractAccountingMismatchVulnerability {
                severity: SecuritySeverity::High,
                description: "Internal accounting diverges from external balances".to_string(),
                location: "Balance tracking".to_string(),
                mismatch_type: MismatchType::InternalExternalMismatch,
                protocols_affected: vec!["External protocol".to_string()],
                impact: "Discrepancy between tracked and actual balances enables theft".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_share_balance_mismatch(&self, bytecode: &[u8]) -> bool {
        // Look for: share calculation (MUL/DIV) + external balance query
        // Different accounting methods
        let convert_to_shares_sig = &[0xc6, 0xe6, 0xd1, 0x85]; // convertToShares()
        let balance_of_sig = &[0x70, 0xa0, 0x82, 0x31]; // balanceOf()
        
        bytecode.windows(4).any(|w| w == convert_to_shares_sig) &&
        bytecode.windows(4).any(|w| w == balance_of_sig) &&
        bytecode.contains(&0x04) // DIV (conversion logic)
    }

    fn has_rebasing_accounting_error(&self, bytecode: &[u8]) -> bool {
        // Look for: balance queries without snapshot/cache mechanism
        // Rebasing tokens require special handling
        let balance_of_sig = &[0x70, 0xa0, 0x82, 0x31];
        
        bytecode.windows(4).any(|w| w == balance_of_sig) &&
        bytecode.windows(50).any(|window| {
            // Balance used directly without caching
            window.contains(&0xfa) && // STATICCALL (balanceOf)
            !window.contains(&0x55) && // No SSTORE (no caching)
            window.contains(&0x04)    // DIV (calc with balance)
        })
    }

    fn has_decimal_mismatch(&self, bytecode: &[u8]) -> bool {
        // Look for: external token operations without decimal normalization
        // Common decimal values: 10**6, 10**18
        let decimals_sig = &[0x31, 0x3c, 0xe5, 0x67]; // decimals()
        
        // Has token operations but NO decimals() call for normalization
        bytecode.contains(&0xf1) && // Has external calls
        !bytecode.windows(4).any(|w| w == decimals_sig) &&
        bytecode.contains(&0x02) // Has MUL (likely needs decimal adjustment)
    }

    fn has_rounding_direction_conflict(&self, bytecode: &[u8]) -> bool {
        // Look for: multiple DIV operations with external calls
        // Different protocols may round differently
        let div_positions: Vec<usize> = bytecode.iter()
            .enumerate()
            .filter(|(_, &op)| op == 0x04)
            .map(|(i, _)| i)
            .collect();

        let external_calls = bytecode.iter().filter(|&&op| op == 0xf1 || op == 0xfa).count();
        
        div_positions.len() >= 2 && external_calls >= 1
    }

    fn has_cumulative_rounding_error(&self, bytecode: &[u8]) -> bool {
        // Look for: loops with divisions (cumulative rounding)
        bytecode.contains(&0x56) && // JUMP (loop)
        bytecode.iter().filter(|&&op| op == 0x04).count() >= 2 && // Multiple DIV
        bytecode.contains(&0xfa) // External call in loop
    }

    fn has_internal_external_mismatch(&self, bytecode: &[u8]) -> bool {
        // Look for: internal balance tracking (SSTORE) separate from external queries
        let balance_of_sig = &[0x70, 0xa0, 0x82, 0x31];
        
        bytecode.windows(4).any(|w| w == balance_of_sig) &&
        bytecode.windows(50).any(|window| {
            window.contains(&0x54) && // SLOAD (internal balance)
            window.contains(&0xfa) && // External balance query
            !window.contains(&0x14)   // No EQ check (not verifying match)
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractAccountingMismatchVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractAccountingMismatch,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!(
                "Cross-Contract Accounting Mismatch: {} - Impact: {}",
                vuln.description, vuln.impact
            ),
            operations: Vec::new(),
            remediation: format!("Review {} - Ensure consistent accounting methods across protocols", vuln.location),
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share_balance_mismatch() {
        let analyzer = CrossContractAccountingMismatchAnalyzer::new();
        
        let bytecode = vec![
            0xc6, 0xe6, 0xd1, 0x85, // convertToShares()
            0x70, 0xa0, 0x82, 0x31, // balanceOf()
            0x04,                     // DIV
        ];
        
        let vulns = analyzer.analyze(&bytecode);
        assert!(!vulns.is_empty());
    }
}
