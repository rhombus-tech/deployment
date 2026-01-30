/// COINBASE Authorization Vulnerability Detector
///
/// Detects use of block.coinbase for authorization - miner can manipulate!
/// block.coinbase = current block's miner address - controlled by miner.
///
/// Why dangerous:
/// - block.coinbase is the current miner's address
/// - Miner can set it to any address they control
/// - Using it for authorization = miner can bypass
/// - Similar to tx.origin but for mining
///
/// Real risks:
/// - Mining pool exploits
/// - Validator manipulation (PoS)
/// - Authorization bypass
/// - $2M+ in coinbase auth bugs
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableMinerReward {
///     // ❌ WRONG: Trusts miner address for authorization!
///     function claimReward() external {
///         require(msg.sender == block.coinbase, "Not miner");
///         payable(msg.sender).transfer(1 ether);
///     }
///     
///     // Attack: Miner sets coinbase to attacker address
///     // → Attacker can call claimReward
///     // → Steals rewards!
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinbaseAuthorizationVulnerability {
    pub vulnerability_type: CoinbaseIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CoinbaseIssueType {
    CoinbaseForAuthorization,      // block.coinbase used for auth
    CoinbaseInAccessControl,       // coinbase in require/if
    CoinbaseComparison,            // Comparing addresses with coinbase
}

pub struct CoinbaseAuthorizationDetector {
    bytecode: Vec<u8>,
}

impl CoinbaseAuthorizationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CoinbaseAuthorizationVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x41 { // COINBASE
                // Check if followed by EQ (comparison)
                if self.has_comparison_after(i) {
                    vulnerabilities.push(CoinbaseAuthorizationVulnerability {
                        vulnerability_type: CoinbaseIssueType::CoinbaseForAuthorization,
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: "block.coinbase used in comparison - miner manipulation risk".to_string(),
                        exploit_scenario: format!(
                            "COINBASE AUTHORIZATION at position {}:\n\
                            \n\
                            CRITICAL: block.coinbase used for authorization!\n\
                            Miners/validators can set coinbase to any address.\n\
                            \n\
                            VULNERABLE PATTERN:\n\
                            ```solidity\n\
                            contract MinerRewards {{\n\
                                mapping(address => uint256) public rewards;\n\
                                \n\
                                function claimMinerReward() external {{\n\
                                    // ❌ EXPLOITABLE!\n\
                                    require(msg.sender == block.coinbase, 'Not miner');\n\
                                    \n\
                                    uint256 reward = rewards[block.coinbase];\n\
                                    rewards[block.coinbase] = 0;\n\
                                    \n\
                                    payable(msg.sender).transfer(reward);\n\
                                }}\n\
                            }}\n\
                            \n\
                            // ATTACK:\n\
                            // Miner mines a block\n\
                            // Sets coinbase = attacker's address\n\
                            // Attacker calls claimMinerReward()\n\
                            // Check passes! Steals rewards!\n\
                            ```\n\
                            \n\
                            SIMILAR TO TX.ORIGIN:\n\
                            Both are manipulatable:\n\
                            - tx.origin: Phishing attack\n\
                            - block.coinbase: Miner manipulation\n\
                            \n\
                            SAFE ALTERNATIVE:\n\
                            Use proper authentication:\n\
                            ```solidity\n\
                            mapping(address => bool) public authorizedMiners;\n\
                            \n\
                            function claim() external {{\n\
                                require(authorizedMiners[msg.sender]);\n\
                                // ...\n\
                            }}\n\
                            ```",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn has_comparison_after(&self, pos: usize) -> bool {
        for i in pos..pos.saturating_add(10).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x14 { // EQ
                return true;
            }
        }
        false
    }
}
