/// Forced Ether Reception Vulnerability Detector
///
/// Detects contracts that assume they can prevent ether reception.
/// SELFDESTRUCT can force-send ether to any contract, bypassing all checks.
///
/// Why dangerous:
/// - Contract logic assumes `address(this).balance == 0`
/// - Attacker uses selfdestruct to force-send ether
/// - Contract invariants broken
/// - Game theory / auction exploits
///
/// Real exploits:
/// - **King of Ether: $100K+** - Forced ether breaks game
/// - **GovernMental: $1.1M** - Balance assumption exploited
/// - Multiple Ponzi schemes broken
/// - Auction manipulation
///
/// Example vulnerability:
/// ```solidity
/// contract KingOfEther {
///     address public king;
///     uint256 public prize;
///     
///     function claimThrone() external payable {
///         require(msg.value > prize);
///         
///         // ❌ WRONG: Assumes balance == prize
///         (bool sent,) = king.call{value: prize}("");
///         require(sent);
///         
///         king = msg.sender;
///         prize = msg.value;
///     }
///     
///     // ATTACK:
///     // 1. Attacker becomes king
///     // 2. Attacker selfdestructs to this contract, sending 1 wei
///     // 3. Now balance != prize
///     // 4. Future refunds fail!
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForcedEtherVulnerability {
    pub vulnerability_type: ForcedEtherIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForcedEtherIssueType {
    BalanceEquality,               // Checks balance == something
    BalanceAssumption,             // Logic depends on exact balance
    RejectingEther,                // Tries to prevent ether reception
    NoReceiveFallback,             // Missing receive/fallback but uses balance
}

pub struct ForcedEtherReceptionDetector {
    bytecode: Vec<u8>,
}

impl ForcedEtherReceptionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ForcedEtherVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_balance_equality_checks());
        vulnerabilities.extend(self.detect_balance_assumptions());

        vulnerabilities
    }

    fn detect_balance_equality_checks(&self) -> Vec<ForcedEtherVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(5) {
            // Look for SELFBALANCE or BALANCE followed by EQ
            if (self.bytecode[i] == 0x47 || self.bytecode[i] == 0x31) { // SELFBALANCE or BALANCE
                // Check for EQ within next few instructions
                for j in i+1..i.saturating_add(10).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 { // EQ
                        vulnerabilities.push(ForcedEtherVulnerability {
                            vulnerability_type: ForcedEtherIssueType::BalanceEquality,
                            severity: SecuritySeverity::Medium,
                            confidence: 0.70,
                            description: "Balance equality check - vulnerable to forced ether".to_string(),
                            exploit_scenario: format!(
                                "BALANCE EQUALITY CHECK at position {}:\n\
                                \n\
                                Contract checks if balance == some value.\n\
                                THIS CAN BE BROKEN via selfdestruct!\n\
                                \n\
                                ATTACK METHOD:\n\
                                ```solidity\n\
                                contract Attacker {{\n\
                                    constructor(address target) payable {{\n\
                                        // Force-send ether to target\n\
                                        selfdestruct(payable(target));\n\
                                        // Target now has ether it didn't expect!\n\
                                    }}\n\
                                }}\n\
                                ```\n\
                                \n\
                                KING OF ETHER HACK:\n\
                                ```solidity\n\
                                contract KingOfEther {{\n\
                                    address public king;\n\
                                    uint256 public prize;\n\
                                    \n\
                                    function becomeKing() external payable {{\n\
                                        require(msg.value > prize);\n\
                                        \n\
                                        // Send back previous prize\n\
                                        (bool sent,) = king.call{{value: prize}}(\"\");\n\
                                        require(sent, 'Transfer failed');\n\
                                        \n\
                                        king = msg.sender;\n\
                                        prize = msg.value;\n\
                                    }}\n\
                                    \n\
                                    function withdraw() external {{\n\
                                        require(msg.sender == king);\n\
                                        \n\
                                        // ❌ VULNERABLE: Assumes balance == prize\n\
                                        require(\n\
                                            address(this).balance == prize,\n\
                                            'Balance mismatch'\n\
                                        );\n\
                                        \n\
                                        (bool sent,) = king.call{{value: prize}}(\"\");\n\
                                        require(sent);\n\
                                    }}\n\
                                }}\n\
                                \n\
                                // ATTACK:\n\
                                // 1. Become king with 1 ETH\n\
                                // 2. Deploy Attacker contract with 1 wei\n\
                                // 3. Attacker selfdestructs to KingOfEther\n\
                                // 4. Now balance = 1 ETH + 1 wei != prize (1 ETH)\n\
                                // 5. withdraw() always reverts!\n\
                                // 6. Funds locked forever!\n\
                                ```\n\
                                \n\
                                SAFE PATTERN:\n\
                                ```solidity\n\
                                contract SafeKing {{\n\
                                    mapping(address => uint256) public balances;\n\
                                    \n\
                                    function deposit() external payable {{\n\
                                        balances[msg.sender] += msg.value;\n\
                                    }}\n\
                                    \n\
                                    function withdraw() external {{\n\
                                        uint256 amount = balances[msg.sender];\n\
                                        balances[msg.sender] = 0;\n\
                                        \n\
                                        // ✓ Use accounting, not balance!\n\
                                        (bool sent,) = msg.sender.call{{value: amount}}(\"\");\n\
                                        require(sent);\n\
                                    }}\n\
                                }}\n\
                                ```\n\
                                \n\
                                RECOMMENDATION:\n\
                                ✗ Never use: balance == value\n\
                                ✓ Use: balance >= value\n\
                                ✓ Better: Track balances in storage\n\
                                ✓ Best: Don't rely on contract balance",
                                i
                            ),
                            location: i,
                        });
                        break;
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_balance_assumptions(&self) -> Vec<ForcedEtherVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Count SELFBALANCE/BALANCE usage
        let balance_count = self.bytecode.iter()
            .filter(|&&b| b == 0x47 || b == 0x31)
            .count();

        if balance_count > 3 {
            vulnerabilities.push(ForcedEtherVulnerability {
                vulnerability_type: ForcedEtherIssueType::BalanceAssumption,
                severity: SecuritySeverity::Medium,
                confidence: 0.50,
                description: format!("Heavy balance usage ({} times) - verify forced ether safety", balance_count),
                exploit_scenario: "Contract frequently checks balance. Ensure logic works if ether is force-sent via selfdestruct.".to_string(),
                location: 0,
            });
        }

        vulnerabilities
    }
}
