/// Cross-Contract Message Replay Detector
///
/// Detects cross-chain message replay vulnerabilities.
/// Risk: LayerZero, Wormhole, Axelar ($50B+ in cross-chain messages)
/// Attack: Replay message on one chain after reverted on another

use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};

#[derive(Debug, Clone)]
pub struct CrossContractMessageReplayVulnerability {
    pub severity: SecuritySeverity,
    pub description: String,
    pub location: String,
    pub replay_type: MessageReplayType,
    pub impact: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MessageReplayType {
    CrossChainNonceReuse,
    MessageIdCollision,
    ChainIdOmission,
    ReplayAfterReorg,
    DuplicateMessageProcessing,
}

pub struct CrossContractMessageReplayAnalyzer;

impl CrossContractMessageReplayAnalyzer {
    pub fn new() -> Self {
        Self
    }

    pub fn analyze(&self, bytecode: &[u8]) -> Vec<CrossContractMessageReplayVulnerability> {
        let mut vulnerabilities = Vec::new();

        if self.has_nonce_reuse_risk(bytecode) {
            vulnerabilities.push(CrossContractMessageReplayVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Cross-chain message nonce can be reused".to_string(),
                location: "Message processing".to_string(),
                replay_type: MessageReplayType::CrossChainNonceReuse,
                impact: "Message replayed on different chain with same nonce".to_string(),
            });
        }

        if self.has_message_id_collision(bytecode) {
            vulnerabilities.push(CrossContractMessageReplayVulnerability {
                severity: SecuritySeverity::Critical,
                description: "Message ID collision enables replay".to_string(),
                location: "Message validation".to_string(),
                replay_type: MessageReplayType::MessageIdCollision,
                impact: "Different messages generate same ID enabling substitution".to_string(),
            });
        }

        if self.has_chain_id_omission(bytecode) {
            vulnerabilities.push(CrossContractMessageReplayVulnerability {
                severity: SecuritySeverity::High,
                description: "Chain ID not included in message hash".to_string(),
                location: "Message hashing".to_string(),
                replay_type: MessageReplayType::ChainIdOmission,
                impact: "Message valid on source chain replayed on destination".to_string(),
            });
        }

        if self.has_reorg_replay_risk(bytecode) {
            vulnerabilities.push(CrossContractMessageReplayVulnerability {
                severity: SecuritySeverity::High,
                description: "Message can be replayed after chain reorg".to_string(),
                location: "Finality checking".to_string(),
                replay_type: MessageReplayType::ReplayAfterReorg,
                impact: "Message reorged on source but already processed on destination".to_string(),
            });
        }

        if self.has_duplicate_processing(bytecode) {
            vulnerabilities.push(CrossContractMessageReplayVulnerability {
                severity: SecuritySeverity::Medium,
                description: "Message processed multiple times across protocols".to_string(),
                location: "Message deduplication".to_string(),
                replay_type: MessageReplayType::DuplicateMessageProcessing,
                impact: "Same message processed in multiple dependent protocols".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_nonce_reuse_risk(&self, bytecode: &[u8]) -> bool {
        // Message processing without proper nonce tracking
        bytecode.windows(50).any(|window| {
            window.contains(&0xf1) && // External call (message)
            !window.contains(&0x54) && // No nonce read
            !window.contains(&0x55)   // No nonce update
        })
    }

    fn has_message_id_collision(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(60).any(|window| {
            window.contains(&0x20) && // SHA3 (message ID)
            !window.contains(&0x46) && // No chain ID included
            !window.contains(&0x33)   // No sender included
        })
    }

    fn has_chain_id_omission(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(40).any(|window| {
            window.contains(&0x20) && // Message hash
            !window.contains(&0x46)   // CHAINID not included
        })
    }

    fn has_reorg_replay_risk(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(50).any(|window| {
            window.contains(&0xf1) && // Cross-chain message
            !window.contains(&0x43) && // No block confirmation check
            !window.contains(&0x42)   // No timestamp finality check
        })
    }

    fn has_duplicate_processing(&self, bytecode: &[u8]) -> bool {
        bytecode.windows(40).any(|window| {
            window.contains(&0xf1) && // Message processing
            !window.contains(&0x54) && // No processed flag check
            !window.contains(&0x55)   // No processed flag set
        })
    }

    pub fn to_security_warnings(&self, vulnerabilities: &[CrossContractMessageReplayVulnerability]) 
        -> Vec<SecurityWarning> {
        vulnerabilities.iter().map(|vuln| SecurityWarning {
            kind: SecurityWarningKind::CrossContractMessageReplay,
            severity: vuln.severity.clone(),
            pc: 0,
            description: format!("Cross-Contract Message Replay: {} - Impact: {}", vuln.description, vuln.impact),
            operations: Vec::new(),
            remediation: format!("Review {} - Implement nonce tracking, chain ID inclusion, and replay protection", vuln.location),
        }).collect()
    }
}
