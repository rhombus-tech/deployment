/// Atomic Cross-Chain Composability Detector
/// Detects vulnerabilities in atomic cross-chain operations
/// Critical for: LayerZero, Axelar, Wormhole, IBC

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomicCrossChainVulnerability {
    pub vulnerability_type: AtomicCrossChainIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AtomicCrossChainIssueType {
    IBCMessageManipulation,        // IBC message tampering
    LayerZeroDVNExploit,           // LayerZero DVN manipulation
    CrossChainFlashloan,           // Atomic flashloan across chains
    MessageReplayAcrossChains,     // Replay message on multiple chains
    OracleDesyncExploit,           // Cross-chain oracle desync
}

pub struct AtomicCrossChainDetector {
    bytecode: Vec<u8>,
}

impl AtomicCrossChainDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<AtomicCrossChainVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.is_cross_chain_protocol() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_message_manipulation());
        vulnerabilities.extend(self.detect_replay_attacks());

        vulnerabilities
    }

    fn detect_message_manipulation(&self) -> Vec<AtomicCrossChainVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Message processing without signature verification
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_message_processing(i) {
                if !self.has_signature_check(i) {
                    vulnerabilities.push(AtomicCrossChainVulnerability {
                        vulnerability_type: AtomicCrossChainIssueType::LayerZeroDVNExploit,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.80,
                        description: "Cross-chain message without signature verification".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Attacker crafts fake cross-chain message\n\
                            2. No DVN signature verification\n\
                            3. Message executed as legitimate\n\
                            4. Funds transferred without authorization\n\n\
                            Fix: Verify DVN/oracle signatures on all messages",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_replay_attacks(&self) -> Vec<AtomicCrossChainVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Message processing without nonce/chain ID check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.has_message_processing(i) {
                if !self.has_nonce_tracking(i) {
                    vulnerabilities.push(AtomicCrossChainVulnerability {
                        vulnerability_type: AtomicCrossChainIssueType::MessageReplayAcrossChains,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Cross-chain message without replay protection".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Valid message delivered on chain A\n\
                            2. No nonce or chain ID validation\n\
                            3. Attacker replays same message on chain B\n\
                            4. Duplicate execution and double-spend\n\n\
                            Fix: Track nonces and validate chain IDs",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn is_cross_chain_protocol(&self) -> bool {
        // Look for message-related functions
        let lz_receive = [0x66, 0xad, 0x5c, 0x8a]; // lzReceive()
        self.bytecode.windows(4).any(|w| w == lz_receive)
    }

    fn has_message_processing(&self, pos: usize) -> bool {
        // Look for CALLDATALOAD (message data)
        pos + 10 < self.bytecode.len() &&
        self.bytecode[pos] == 0x35 // CALLDATALOAD
    }

    fn has_signature_check(&self, pos: usize) -> bool {
        // Look for ECRECOVER or signature verification pattern
        for i in pos..pos.saturating_add(50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x60 && i + 1 < self.bytecode.len() && self.bytecode[i+1] == 0x01 {
                // PUSH1 0x01 (ecrecover precompile)
                return true;
            }
        }
        false
    }

    fn has_nonce_tracking(&self, pos: usize) -> bool {
        // Look for SLOAD/SSTORE pattern (nonce storage)
        let mut has_sload = false;
        let mut has_sstore = false;
        for i in pos..pos.saturating_add(50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x54 { has_sload = true; }
            if self.bytecode[i] == 0x55 { has_sstore = true; }
        }
        has_sload && has_sstore
    }
}
