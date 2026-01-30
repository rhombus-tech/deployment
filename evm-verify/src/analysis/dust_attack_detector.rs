/// Dust Attack Vulnerability Detector
///
/// Detects vulnerabilities related to tiny value transfers that can break contract logic.
/// "Dust" = very small amounts (wei-level) that bypass validation or break accounting.
///
/// Why dangerous:
/// - Minimum amount checks can be bypassed with 1 wei
/// - Precision loss in division with tiny amounts
/// - Fee calculations fail (0.1% of 1 wei = 0)
/// - Accounting errors accumulate
/// - DoS via dust spam
///
/// Attack vectors:
/// - Send 1 wei to bypass "minimum deposit" checks
/// - Spam contract with dust to bloat state
/// - Break fee calculations (amount too small for fees)
/// - Cause rounding errors in accounting
///
/// Real impacts:
/// - DEX pools manipulated with dust
/// - Vault accounting broken
/// - Fee bypass in protocols
/// - $1M+ in cumulative bugs
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableVault {
///     mapping(address => uint256) public balances;
///     uint256 public constant FEE_BPS = 10; // 0.1%
///     
///     function deposit() external payable {
///         // ❌ No minimum check!
///         uint256 fee = msg.value * FEE_BPS / 10000;
///         
///         // If msg.value = 100 wei:
///         // fee = 100 * 10 / 10000 = 0 (rounds down!)
///         // User deposits without paying fees!
///         
///         balances[msg.sender] += msg.value - fee;
///         // fee = 0, so full amount deposited
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DustAttackVulnerability {
    pub vulnerability_type: DustIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DustIssueType {
    MissingMinimumAmount,          // No minimum transfer check
    FeeBypassViaDust,              // Fee calculation fails on tiny amounts
    PrecisionLossOnDust,           // Division by large number loses precision
    DustSpamVulnerability,         // No protection against dust spam
    AccountingErrorOnDust,         // Accounting breaks with tiny values
}

pub struct DustAttackDetector {
    bytecode: Vec<u8>,
}

impl DustAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DustAttackVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_missing_minimum_check());
        vulnerabilities.extend(self.detect_fee_calculation_without_minimum());
        vulnerabilities.extend(self.detect_division_precision_loss());

        vulnerabilities
    }

    fn detect_missing_minimum_check(&self) -> Vec<DustAttackVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for payable functions (CALLVALUE) without minimum check
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x34 { // CALLVALUE
                // Check if there's a GT/LT comparison nearby (minimum check)
                if !self.has_amount_validation_after(i) {
                    vulnerabilities.push(DustAttackVulnerability {
                        vulnerability_type: DustIssueType::MissingMinimumAmount,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "Payable function without minimum amount check".to_string(),
                        exploit_scenario: format!(
                            "NO MINIMUM CHECK at position {}:\n\
                            \n\
                            Function accepts ETH without validating minimum amount.\n\
                            \n\
                            Risks:\n\
                            - Dust spam (1 wei deposits bloat state)\n\
                            - Fee bypass (amounts too small for fees)\n\
                            - Precision loss in calculations\n\
                            - Accounting errors\n\
                            \n\
                            Fix: require(msg.value >= MIN_AMOUNT)",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_fee_calculation_without_minimum(&self) -> Vec<DustAttackVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: CALLVALUE → MUL → DIV (fee calculation)
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x34 { // CALLVALUE
                // Look for MUL followed by DIV (typical fee calculation)
                for j in i..i+15 {
                    if j < self.bytecode.len() && self.bytecode[j] == 0x02 { // MUL
                        for k in j..j+10 {
                            if k < self.bytecode.len() && self.bytecode[k] == 0x04 { // DIV
                                vulnerabilities.push(DustAttackVulnerability {
                                    vulnerability_type: DustIssueType::FeeBypassViaDust,
                                    severity: SecuritySeverity::Medium,
                                    confidence: 0.65,
                                    description: "Fee calculation vulnerable to dust bypass".to_string(),
                                    exploit_scenario: format!(
                                        "FEE BYPASS at position {}:\n\
                                        \n\
                                        Fee calculation: amount * fee / divisor\n\
                                        \n\
                                        With tiny amounts:\n\
                                        - 100 wei * 10 / 10000 = 0 (rounds down)\n\
                                        - User deposits without paying fees!\n\
                                        \n\
                                        Fix: Enforce minimum amount OR check fee != 0",
                                        i
                                    ),
                                    location: i,
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_division_precision_loss(&self) -> Vec<DustAttackVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for DIV operations that could lose precision
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x04 { // DIV
                // Check if divisor is large constant
                if self.has_large_divisor_before(i) {
                    vulnerabilities.push(DustAttackVulnerability {
                        vulnerability_type: DustIssueType::PrecisionLossOnDust,
                        severity: SecuritySeverity::Low,
                        confidence: 0.60,
                        description: "Division by large number - precision loss on small values".to_string(),
                        exploit_scenario: format!(
                            "PRECISION LOSS at position {}:\n\
                            \n\
                            Division by large constant (10000, 1e18, etc.)\n\
                            Small values round to zero.\n\
                            \n\
                            Example: 100 / 10000 = 0\n\
                            \n\
                            Recommendation: Validate input > divisor",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn has_amount_validation_after(&self, pos: usize) -> bool {
        // Look for GT or LT comparison (minimum check)
        for i in pos..pos.saturating_add(20).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 { // LT or GT
                return true;
            }
        }
        false
    }

    fn has_large_divisor_before(&self, pos: usize) -> bool {
        // Check for PUSH of large number (>1000) before DIV
        for i in pos.saturating_sub(10)..pos {
            if self.bytecode[i] >= 0x60 && self.bytecode[i] <= 0x7F {
                let push_size = (self.bytecode[i] - 0x5F) as usize;
                if i + push_size < self.bytecode.len() {
                    let mut value: u64 = 0;
                    for j in 0..push_size.min(8) {
                        value = (value << 8) | self.bytecode[i + 1 + j] as u64;
                    }
                    if value >= 1000 {
                        return true;
                    }
                }
            }
        }
        false
    }
}
