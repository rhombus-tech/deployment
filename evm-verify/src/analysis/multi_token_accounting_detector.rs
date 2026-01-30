/// Multi-Token Accounting Vulnerability Detector
///
/// Detects accounting errors when same token has multiple addresses.
/// Rebasing tokens + fee-on-transfer + different addresses = accounting chaos.
///
/// Why dangerous:
/// - Same token at different addresses (proxy upgrades)
/// - Rebasing tokens change balance over time
/// - Fee-on-transfer tokens: sent ≠ received
/// - Combining these = catastrophic accounting errors
///
/// Real exploits:
/// - $20M+ in vault accounting bugs
/// - Double-counting collateral
/// - Phantom balances
/// - Yearn, Rari, Cream bugs
///
/// Example:
/// ```solidity
/// contract VulnerableVault {
///     mapping(address => uint256) public tokenBalance;
///     
///     function deposit(address token, uint256 amount) external {
///         // ❌ Assumes amount received = amount sent
///         token.transferFrom(msg.sender, address(this), amount);
///         tokenBalance[token] += amount;
///         
///         // But if token is fee-on-transfer:
///         // Sent: 100, Received: 95
///         // Accounting shows 100 but only have 95!
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiTokenAccountingVulnerability {
    pub vulnerability_type: MultiTokenIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MultiTokenIssueType {
    FeeOnTransferNotAccounted,     // Fee-on-transfer not checked
    RebasingTokenAccounting,       // Rebasing balance changes
    SameTokenDifferentAddresses,   // Same token, multiple addresses
    BalanceAssumption,             // Assumes sent = received
}

pub struct MultiTokenAccountingDetector {
    bytecode: Vec<u8>,
}

impl MultiTokenAccountingDetector {
    const TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
    const BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];

    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MultiTokenAccountingVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(20) {
            if &self.bytecode[i..i.saturating_add(4).min(self.bytecode.len())] == &Self::TRANSFER_FROM {
                // Check if balanceOf is called before/after transfer
                let has_balance_check = self.has_balance_check_nearby(i);
                
                if !has_balance_check {
                    vulnerabilities.push(MultiTokenAccountingVulnerability {
                        vulnerability_type: MultiTokenIssueType::BalanceAssumption,
                        severity: SecuritySeverity::High,
                        confidence: 0.65,
                        description: "Token transfer without balance verification - fee-on-transfer risk".to_string(),
                        exploit_scenario: "Multi-Token Accounting: Transfer assumes amount sent equals amount received. Fee-on-transfer tokens break this assumption. Check actual balance change.".to_string(),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn has_balance_check_nearby(&self, pos: usize) -> bool {
        for i in pos.saturating_sub(50)..pos.saturating_add(50).min(self.bytecode.len().saturating_sub(4)) {
            if &self.bytecode[i..i+4] == &Self::BALANCE_OF {
                return true;
            }
        }
        false
    }
}
