/// Cross-L2 Bridge Specific Vulnerability Analyzer
/// Extends bridge_security.rs with L2-to-L2 specific patterns

use serde::{Serialize, Deserialize};
use crate::bytecode::security::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossL2BridgeVulnerability {
    pub vulnerability_type: CrossL2VulnType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CrossL2VulnType {
    L2ToL2MessageReplay,
    OptimisticBridgeProofManipulation,
    CrossRollupReentrancy,
    SequencerCollusionAttack,
    FastWithdrawalTiming,
}

pub struct CrossL2BridgeAnalyzer {
    bytecode: Vec<u8>,
}

impl CrossL2BridgeAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CrossL2BridgeVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_cross_l2_bridge() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_message_replay());
        vulnerabilities.extend(self.detect_cross_rollup_reentrancy());

        vulnerabilities
    }

    fn is_cross_l2_bridge(&self) -> bool {
        let bridge_sigs = [
            &[0x8d, 0x96, 0xfd, 0xea][..], // sendCrossChainMessage()
            &[0x47, 0x33, 0x33, 0x9a][..], // relayMessage()
        ];

        bridge_sigs.iter().any(|&sig| {
            self.bytecode.windows(sig.len()).any(|w| w == sig)
        })
    }

    fn detect_message_replay(&self) -> Vec<CrossL2BridgeVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0x20 { // SHA3 (message hash)
                let no_nonce = !self.bytecode[i.saturating_sub(50)..i+50]
                    .windows(1).filter(|w| w[0] == 0x54).count() >= 2;

                if no_nonce {
                    vulnerabilities.push(CrossL2BridgeVulnerability {
                        vulnerability_type: CrossL2VulnType::L2ToL2MessageReplay,
                        severity: SecuritySeverity::Critical,
                        location: i,
                        description: "Cross-L2 messages lack replay protection".to_string(),
                        exploit_scenario: "L2-to-L2 Message Replay:\n\
                            1. User bridges 100 USDC from Arbitrum to Optimism\n\
                            2. Message relayed successfully\n\
                            3. No nonce or message hash tracking\n\
                            4. Attacker replays same message\n\
                            5. User receives 100 USDC again\n\
                            6. Bridge becomes insolvent\n\
                            \n\
                            Critical: Cross-L2 bridges need replay protection".to_string(),
                        remediation: "Add replay protection:\n\
                            1. Message nonce tracking\n\
                            2. Hash-based deduplication\n\
                            3. Cross-chain nonce coordination\n\
                            4. Message expiry timestamps".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_cross_rollup_reentrancy(&self) -> Vec<CrossL2BridgeVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0xF1 { // CALL (cross-chain call)
                let no_reentrancy_guard = !self.bytecode[i.saturating_sub(30)..i]
                    .windows(3).any(|w| w[0] == 0x54 && w[1] == 0x15);

                if no_reentrancy_guard {
                    vulnerabilities.push(CrossL2BridgeVulnerability {
                        vulnerability_type: CrossL2VulnType::CrossRollupReentrancy,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Cross-rollup calls allow reentrancy".to_string(),
                        exploit_scenario: "Cross-Rollup Reentrancy:\n\
                            1. Arbitrum bridge calls Optimism bridge\n\
                            2. Optimism contract reenters Arbitrum\n\
                            3. State not yet finalized on Arbitrum\n\
                            4. Double-spend across chains\n\
                            \n\
                            Impact: Cross-chain state inconsistency".to_string(),
                        remediation: "Reentrancy guards for cross-chain calls".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }
}
