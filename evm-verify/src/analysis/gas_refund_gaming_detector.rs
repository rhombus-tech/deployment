/// Gas Refund Gaming Vulnerability Detector
///
/// Detects manipulation of SSTORE gas refunds to gain unfair gas advantages.
/// EVM refunds gas when storage is freed (set to zero), but this can be exploited.
///
/// Gas refund mechanics (pre-London):
/// - SSTORE from non-zero to zero: 15,000 gas refund
/// - Max refund: 50% of gas used in transaction
/// - Attackers can manipulate refunds to subsidize expensive operations
///
/// Post-London (EIP-3529):
/// - Refunds capped more tightly
/// - But still exploitable patterns exist
///
/// Why dangerous:
/// - Free expensive operations via refund manipulation
/// - Gas token arbitrage (GasToken, CHI)
/// - Unfair MEV extraction
/// - DoS via refund exhaustion
///
/// Real exploits:
/// - GasToken manipulation: $10M+ in arbitrage
/// - Flash loan + storage manipulation
/// - Griefing attacks via refund gaming
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableRefund {
///     mapping(uint256 => uint256) public data;
///     
///     function processWithRefund(uint256[] calldata ids) external {
///         // ❌ Attacker can game refunds
///         for (uint i = 0; i < ids.length; i++) {
///             // Store then delete to get refund
///             data[ids[i]] = 1;
///             delete data[ids[i]];  // Refund!
///         }
///         
///         // Expensive operation subsidized by refunds
///         expensiveComputation();
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasRefundVulnerability {
    pub vulnerability_type: GasRefundIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GasRefundIssueType {
    StorageRefundManipulation,     // SSTORE patterns for refund gaming
    RefundInLoop,                  // Repeated refund operations
    ClearingStorageForRefund,      // Deleting storage for refunds
    GasTokenPattern,               // Gas token-like behavior
    RefundBasedLogic,              // Logic depends on refund amount
}

pub struct GasRefundGamingDetector {
    bytecode: Vec<u8>,
}

impl GasRefundGamingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<GasRefundVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_storage_clear_pattern());
        vulnerabilities.extend(self.detect_refund_in_loop());
        vulnerabilities.extend(self.detect_gas_token_pattern());

        vulnerabilities
    }

    fn detect_storage_clear_pattern(&self) -> Vec<GasRefundVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: SSTORE 0 (clearing storage for refund)
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check if storing zero value
                if self.has_zero_value_before(i) {
                    vulnerabilities.push(GasRefundVulnerability {
                        vulnerability_type: GasRefundIssueType::ClearingStorageForRefund,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "Storage cleared to zero - potential refund manipulation".to_string(),
                        exploit_scenario: format!(
                            "STORAGE CLEARING at position {}:\n\
                            \n\
                            SSTORE to zero detected - gas refund manipulation risk.\n\
                            \n\
                            REFUND GAMING PATTERN:\n\
                            ```solidity\n\
                            contract RefundGaming {{\n\
                                mapping(uint256 => uint256) public slots;\n\
                                \n\
                                function gameRefunds(uint256[] calldata ids) external {{\n\
                                    // ❌ Store then immediately delete\n\
                                    for (uint i = 0; i < ids.length; i++) {{\n\
                                        slots[ids[i]] = block.timestamp;\n\
                                        delete slots[ids[i]];  // Get refund!\n\
                                    }}\n\
                                    \n\
                                    // Refunds subsidize this expensive call\n\
                                    expensiveOperation();\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            GAS TOKEN ATTACK:\n\
                            ```solidity\n\
                            contract GasToken {{\n\
                                uint256[] public slots;\n\
                                \n\
                                // Mint when gas is cheap\n\
                                function mint(uint256 amount) external {{\n\
                                    for (uint i = 0; i < amount; i++) {{\n\
                                        slots.push(1);  // Store when cheap\n\
                                    }}\n\
                                }}\n\
                                \n\
                                // Burn when gas is expensive\n\
                                function free(uint256 amount) external {{\n\
                                    for (uint i = 0; i < amount; i++) {{\n\
                                        delete slots[i];  // Get refund when expensive!\n\
                                    }}\n\
                                    // Use refunds to subsidize expensive ops\n\
                                }}\n\
                            }}\n\
                            ```\n\
                            \n\
                            REAL EXPLOIT:\n\
                            1. When gas = 10 gwei: Store 1000 slots (costs 20M gas)\n\
                            2. When gas = 200 gwei: Delete 1000 slots\n\
                            3. Get 15M gas refund at 200 gwei = 3 ETH subsidy\n\
                            4. Net profit from gas arbitrage\n\
                            \n\
                            IMPACT:\n\
                            - Unfair gas advantages\n\
                            - MEV extraction\n\
                            - Network congestion\n\
                            - Flash loan + refund attacks\n\
                            \n\
                            MITIGATION:\n\
                            - EIP-3529 reduced refunds post-London\n\
                            - Avoid storage operations in user-controlled loops\n\
                            - Monitor for gas token patterns\n\
                            - Rate limit storage clearing operations",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_refund_in_loop(&self) -> Vec<GasRefundVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x55 && self.is_in_loop(i) {
                if self.has_zero_value_before(i) {
                    vulnerabilities.push(GasRefundVulnerability {
                        vulnerability_type: GasRefundIssueType::RefundInLoop,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Storage clearing in loop - refund gaming amplified".to_string(),
                        exploit_scenario: format!(
                            "REFUND IN LOOP at position {}:\n\
                            \n\
                            Storage cleared in loop - multiplied refund manipulation.\n\
                            \n\
                            Attack: Clear 100 slots → 1.5M gas refund\n\
                            This subsidizes expensive operations in same transaction.",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_gas_token_pattern(&self) -> Vec<GasRefundVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for array operations + storage clearing (gas token pattern)
        let has_array_ops = self.bytecode.iter().any(|&b| b == 0x31); // BALANCE (used in some patterns)
        let has_storage_clear = self.bytecode.iter().enumerate().any(|(i, &b)| {
            b == 0x55 && self.has_zero_value_before(i)
        });

        if has_array_ops && has_storage_clear {
            vulnerabilities.push(GasRefundVulnerability {
                vulnerability_type: GasRefundIssueType::GasTokenPattern,
                severity: SecuritySeverity::Medium,
                confidence: 0.65,
                description: "Potential gas token pattern detected".to_string(),
                exploit_scenario: "Contract exhibits gas token-like behavior: array operations + storage clearing for refunds. This may be used for gas arbitrage.".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }

    fn has_zero_value_before(&self, pos: usize) -> bool {
        for i in pos.saturating_sub(10)..pos {
            if self.bytecode[i] == 0x60 && i + 1 < self.bytecode.len() &&
               self.bytecode[i + 1] == 0x00 {
                return true;
            }
        }
        false
    }

    fn is_in_loop(&self, pos: usize) -> bool {
        let has_jumpdest = self.bytecode[..pos].iter().rev().take(50).any(|&b| b == 0x5B);
        let has_jumpi = self.bytecode[pos..].iter().take(50).any(|&b| b == 0x57);
        has_jumpdest && has_jumpi
    }
}
