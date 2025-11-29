/// Native Asset Wrapping (ETH/WETH, etc) Vulnerability Analyzer
/// Targets: WETH, Wrapped native assets, Gas token mechanics

use serde::{Serialize, Deserialize};
use crate::bytecode::security::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeWrappingVulnerability {
    pub vulnerability_type: NativeWrappingVulnType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NativeWrappingVulnType {
    DepositWithdrawalReentrancy,
    ETHWETHArbitrageExploit,
    GasTokenManipulation,
    CrossChainWrappingMismatch,
    Permit2IntegrationIssue,
}

pub struct NativeWrappingAnalyzer {
    bytecode: Vec<u8>,
}

impl NativeWrappingAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<NativeWrappingVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_wrapping_contract() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_deposit_withdrawal_reentrancy());
        vulnerabilities.extend(self.detect_eth_weth_arbitrage());
        
        vulnerabilities
    }

    fn is_wrapping_contract(&self) -> bool {
        let wrap_sigs = [
            &[0xd0, 0xe3, 0x0d, 0xb0][..], // deposit()
            &[0x2e, 0x1a, 0x7d, 0x4d][..], // withdraw()
        ];

        wrap_sigs.iter().any(|&sig| {
            self.bytecode.windows(sig.len()).any(|w| w == sig)
        })
    }

    fn detect_deposit_withdrawal_reentrancy(&self) -> Vec<NativeWrappingVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0xF0 || self.bytecode[i] == 0xF1 { // CREATE or CALL
                let transfers_eth = self.bytecode[i.saturating_sub(20)..i]
                    .windows(1).any(|w| w[0] == 0x31); // BALANCE check

                let no_reentrancy_guard = !self.bytecode[i.saturating_sub(30)..i]
                    .windows(3).any(|w| w[0] == 0x54 && w[1] == 0x15 && w[2] == 0x57);

                if transfers_eth && no_reentrancy_guard {
                    vulnerabilities.push(NativeWrappingVulnerability {
                        vulnerability_type: NativeWrappingVulnType::DepositWithdrawalReentrancy,
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "WETH deposit/withdrawal vulnerable to reentrancy".to_string(),
                        exploit_scenario: "WETH Reentrancy:\n\
                            1. Attacker deposits 10 ETH, gets 10 WETH\n\
                            2. Calls withdraw(10 WETH)\n\
                            3. Contract sends 10 ETH to attacker\n\
                            4. Attacker's receive() reenters withdraw\n\
                            5. Balance not yet updated, withdraws another 10 ETH\n\
                            6. Drains contract\n\
                            \n\
                            Classic: Why reentrancy guards essential for native transfers".to_string(),
                        remediation: "Add reentrancy protection:\n\
                            1. ReentrancyGuard modifier\n\
                            2. Checks-effects-interactions\n\
                            3. Update balances before transfer\n\
                            4. Use pull payment pattern".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_eth_weth_arbitrage(&self) -> Vec<NativeWrappingVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0x31 { // BALANCE (ETH balance check)
                let used_for_pricing = self.bytecode[i+1..i+50]
                    .windows(1).any(|w| w[0] == 0x04); // DIV

                if used_for_pricing {
                    vulnerabilities.push(NativeWrappingVulnerability {
                        vulnerability_type: NativeWrappingVulnType::ETHWETHArbitrageExploit,
                        severity: SecuritySeverity::Medium,
                        location: i,
                        description: "ETH balance used for pricing creates arbitrage opportunity".to_string(),
                        exploit_scenario: "ETH/WETH Arbitrage:\n\
                            1. Protocol prices based on ETH balance\n\
                            2. Attacker deposits large ETH\n\
                            3. Price temporarily distorted\n\
                            4. Withdraws immediately\n\
                            5. Profits from price movement\n\
                            \n\
                            Impact: Flash arbitrage on wrapping".to_string(),
                        remediation: "Use WETH totalSupply for pricing, not ETH balance".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }
}
