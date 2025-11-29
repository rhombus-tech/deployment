/// Cross-Chain Message Passing Analyzer
/// Detects vulnerabilities in cross-chain bridges and message passing systems
/// Critical for: Bridges, cross-chain protocols, LayerZero, Wormhole, etc.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CrossChainVulnerabilityType {
    MessageReplayAttack,         // Messages can be replayed on different chains
    CrossChainReentrancy,        // Reentrancy across chain boundaries
    BridgeMessageManipulation,   // Bridge messages can be manipulated
    ChainIdValidationMissing,    // Doesn't validate source chain ID
    NonceManagementIssue,        // Improper nonce tracking across chains
    SignatureReplayAcrossChains, // Signatures valid on multiple chains
    InconsistentStateHandling,   // State inconsistencies across chains
    OracleManipulationRisk,      // Cross-chain oracles can be manipulated
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecuritySeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainVulnerability {
    pub vulnerability_type: CrossChainVulnerabilityType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub remediation: String,
}

pub struct CrossChainAnalyzer {
    bytecode: Vec<u8>,
}

impl CrossChainAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CrossChainVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_message_replay());
        vulnerabilities.extend(self.detect_cross_chain_reentrancy());
        vulnerabilities.extend(self.detect_chain_id_validation());
        vulnerabilities.extend(self.detect_nonce_management_issues());
        vulnerabilities.extend(self.detect_signature_replay());

        vulnerabilities
    }

    fn detect_message_replay(&self) -> Vec<CrossChainVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Bridge receive message signatures
        let receive_sigs = [
            &[0x1f, 0x7b, 0x6d, 0x32][..], // receiveMessage(bytes)
            &[0x7d, 0x62, 0x5f, 0x38][..], // executeBridgeMessage(...)
            &[0x4a, 0x79, 0x38, 0x6b][..], // lzReceive(...) - LayerZero
        ];

        for sig in receive_sigs.iter() {
            if let Some(pos) = self.bytecode.windows(4).position(|w| w == *sig) {
                // Check for nonce/sequence tracking
                let has_nonce_check = self.bytecode[pos..pos.saturating_add(80).min(self.bytecode.len())]
                    .windows(10)
                    .any(|w| {
                        w.contains(&0x54) && // SLOAD (read nonce)
                        w.contains(&0x10) && // LT (nonce > stored)
                        w.contains(&0x55)    // SSTORE (update nonce)
                    });

                // Check for message hash storage (replay prevention)
                let has_message_hash_storage = self.bytecode[pos..pos.saturating_add(80).min(self.bytecode.len())]
                    .windows(8)
                    .any(|w| {
                        w.contains(&0x20) && // KECCAK256 (message hash)
                        w.contains(&0x55)    // SSTORE (store hash)
                    });

                // Check for chain ID in message hash
                let includes_chain_id = self.bytecode[pos..pos.saturating_add(80).min(self.bytecode.len())]
                    .iter()
                    .any(|&op| op == 0x46); // CHAINID

                if !has_nonce_check && !has_message_hash_storage {
                    vulnerabilities.push(CrossChainVulnerability {
                        vulnerability_type: CrossChainVulnerabilityType::MessageReplayAttack,
                        severity: SecuritySeverity::Critical,
                        location: pos,
                        description: "Bridge message lacks replay protection. Same message can be executed multiple times.".to_string(),
                        remediation: "Store message hash or nonce: require(!processedMessages[msgHash]); processedMessages[msgHash] = true".to_string(),
                    });
                }

                if has_message_hash_storage && !includes_chain_id {
                    vulnerabilities.push(CrossChainVulnerability {
                        vulnerability_type: CrossChainVulnerabilityType::MessageReplayAttack,
                        severity: SecuritySeverity::High,
                        location: pos,
                        description: "Message hash doesn't include chain ID. Message could replay on forks or different chains.".to_string(),
                        remediation: "Include chain ID in hash: keccak256(abi.encodePacked(chainId, nonce, payload))".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_cross_chain_reentrancy(&self) -> Vec<CrossChainVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Bridge send/receive patterns
        let send_sigs = [
            &[0xa6, 0x8a, 0x76, 0xcc][..], // sendMessage(...)
            &[0xd5, 0x39, 0x13, 0x93][..], // bridgeSend(...)
        ];

        let receive_sigs = [
            &[0x1f, 0x7b, 0x6d, 0x32][..], // receiveMessage(...)
            &[0x4a, 0x79, 0x38, 0x6b][..], // lzReceive(...)
        ];

        // Check if contract both sends and receives messages
        let has_send = send_sigs.iter().any(|sig| {
            self.bytecode.windows(4).any(|w| w == *sig)
        });

        let has_receive = receive_sigs.iter().any(|sig| {
            self.bytecode.windows(4).any(|w| w == *sig)
        });

        if has_send && has_receive {
            // Look for external calls in receive functions
            for sig in receive_sigs.iter() {
                if let Some(pos) = self.bytecode.windows(4).position(|w| w == *sig) {
                    // Check for external calls (CALL, DELEGATECALL)
                    let has_external_call = self.bytecode[pos..pos.saturating_add(100).min(self.bytecode.len())]
                        .iter()
                        .any(|&op| op == 0xf1 || op == 0xf4);

                    // Check for reentrancy guard
                    let has_reentrancy_guard = self.bytecode[pos..pos.saturating_add(40).min(self.bytecode.len())]
                        .windows(5)
                        .any(|w| {
                            w.contains(&0x54) && // SLOAD (lock check)
                            w.contains(&0x15) && // ISZERO
                            w.contains(&0x57)    // JUMPI (revert if locked)
                        });

                    if has_external_call && !has_reentrancy_guard {
                        vulnerabilities.push(CrossChainVulnerability {
                            vulnerability_type: CrossChainVulnerabilityType::CrossChainReentrancy,
                            severity: SecuritySeverity::Critical,
                            location: pos,
                            description: "Cross-chain message handler makes external calls without reentrancy protection. Attacker can reenter via another chain.".to_string(),
                            remediation: "Add nonReentrant modifier to all bridge receive functions that make external calls.".to_string(),
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_chain_id_validation(&self) -> Vec<CrossChainVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Bridge message receive functions
        let receive_sigs = [
            &[0x1f, 0x7b, 0x6d, 0x32][..], // receiveMessage
            &[0x4a, 0x79, 0x38, 0x6b][..], // lzReceive
            &[0x7d, 0x62, 0x5f, 0x38][..], // executeBridgeMessage
        ];

        for sig in receive_sigs.iter() {
            if let Some(pos) = self.bytecode.windows(4).position(|w| w == *sig) {
                // Check for CHAINID opcode usage
                let has_chainid_check = self.bytecode[pos..pos.saturating_add(80).min(self.bytecode.len())]
                    .windows(10)
                    .any(|w| {
                        w.contains(&0x46) && // CHAINID
                        (w.contains(&0x14) || w.contains(&0x10)) // EQ or LT comparison
                    });

                // Check for source chain validation parameter
                let has_source_validation = self.bytecode[pos..pos.saturating_add(80).min(self.bytecode.len())]
                    .windows(8)
                    .any(|w| {
                        w.contains(&0x54) && // SLOAD (trusted chains)
                        w.contains(&0x14) && // EQ (validate source)
                        w.contains(&0x57)    // JUMPI (revert if invalid)
                    });

                if !has_chainid_check && !has_source_validation {
                    vulnerabilities.push(CrossChainVulnerability {
                        vulnerability_type: CrossChainVulnerabilityType::ChainIdValidationMissing,
                        severity: SecuritySeverity::High,
                        location: pos,
                        description: "Bridge message doesn't validate source chain ID. Messages from untrusted chains can be processed.".to_string(),
                        remediation: "Validate source chain: require(trustedChains[srcChainId], 'Untrusted source')".to_string(),
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_nonce_management_issues(&self) -> Vec<CrossChainVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for nonce incrementation patterns
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Pattern: SLOAD nonce, ADD 1, SSTORE nonce
            if self.bytecode[i] == 0x54 { // SLOAD
                let window = &self.bytecode[i..i.saturating_add(20).min(self.bytecode.len())];
                
                let has_increment = window.windows(3).any(|w| {
                    w[0] == 0x60 && w[1] == 0x01 && // PUSH1 1
                    w[2] == 0x01    // ADD
                });

                let has_sstore = window.contains(&0x55);

                if has_increment && has_sstore {
                    // Check if this is per-chain nonce (good) or global (bad)
                    let uses_chainid = window.contains(&0x46); // CHAINID in nonce key

                    // Check for overflow protection
                    let has_overflow_check = window.windows(5).any(|w| {
                        w.contains(&0x10) && // LT (check overflow)
                        w.contains(&0x15)    // ISZERO
                    });

                    if !uses_chainid {
                        vulnerabilities.push(CrossChainVulnerability {
                            vulnerability_type: CrossChainVulnerabilityType::NonceManagementIssue,
                            severity: SecuritySeverity::High,
                            location: i,
                            description: "Nonce is global across all chains. Nonce collision risk when interacting with multiple chains.".to_string(),
                            remediation: "Use per-chain nonces: mapping(uint256 => uint256) chainNonces; nonce = chainNonces[srcChainId]++".to_string(),
                        });
                    }

                    if !has_overflow_check {
                        vulnerabilities.push(CrossChainVulnerability {
                            vulnerability_type: CrossChainVulnerabilityType::NonceManagementIssue,
                            severity: SecuritySeverity::Medium,
                            location: i,
                            description: "Nonce increment lacks overflow protection. Could wrap around after 2^256 messages.".to_string(),
                            remediation: "Use SafeMath or check: require(newNonce > oldNonce, 'Nonce overflow')".to_string(),
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_signature_replay(&self) -> Vec<CrossChainVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for signature verification patterns
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // ecrecover pattern: PUSH1 0x01 (ecrecover precompile)
            if i + 3 < self.bytecode.len() && 
               self.bytecode[i] == 0x60 && self.bytecode[i+1] == 0x01 {
                
                let window = &self.bytecode[i..i.saturating_add(50).min(self.bytecode.len())];
                
                // Check if STATICCALL is used (calling ecrecover)
                let has_staticcall = window.contains(&0xfa);
                
                if has_staticcall {
                    // Check if chain ID is in the signed message
                    let includes_chainid = window.contains(&0x46); // CHAINID

                    // Check if contract address is in signed message
                    let includes_address = window.contains(&0x30); // ADDRESS

                    if !includes_chainid {
                        vulnerabilities.push(CrossChainVulnerability {
                            vulnerability_type: CrossChainVulnerabilityType::SignatureReplayAcrossChains,
                            severity: SecuritySeverity::Critical,
                            location: i,
                            description: "Signature verification doesn't include chain ID. Signature can be replayed on different chains or forks.".to_string(),
                            remediation: "Include chain ID in signature: hash = keccak256(abi.encodePacked(chainId, address(this), nonce, data))".to_string(),
                        });
                    }

                    if !includes_address {
                        vulnerabilities.push(CrossChainVulnerability {
                            vulnerability_type: CrossChainVulnerabilityType::SignatureReplayAcrossChains,
                            severity: SecuritySeverity::High,
                            location: i,
                            description: "Signature doesn't include contract address. Signature valid for any contract deployment on any chain.".to_string(),
                            remediation: "Include contract address: hash = keccak256(abi.encodePacked(address(this), ...))".to_string(),
                        });
                    }
                }
            }
        }

        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_message_replay() {
        let bytecode = vec![
            0x1f, 0x7b, 0x6d, 0x32, // receiveMessage
            0xf1, // CALL (executes message without replay protection)
        ];

        let analyzer = CrossChainAnalyzer::new(bytecode);
        let vulnerabilities = analyzer.detect_vulnerabilities();

        assert!(vulnerabilities.iter().any(|v| {
            matches!(v.vulnerability_type, CrossChainVulnerabilityType::MessageReplayAttack)
        }));
    }

    #[test]
    fn test_detect_cross_chain_reentrancy() {
        let bytecode = vec![
            0xa6, 0x8a, 0x76, 0xcc, // sendMessage
            0x1f, 0x7b, 0x6d, 0x32, // receiveMessage
            0xf1, // CALL (external call without reentrancy guard)
        ];

        let analyzer = CrossChainAnalyzer::new(bytecode);
        let vulnerabilities = analyzer.detect_vulnerabilities();

        assert!(vulnerabilities.iter().any(|v| {
            matches!(v.vulnerability_type, CrossChainVulnerabilityType::CrossChainReentrancy)
        }));
    }

    #[test]
    fn test_safe_cross_chain_messaging() {
        let bytecode = vec![
            0x1f, 0x7b, 0x6d, 0x32, // receiveMessage
            0x46, // CHAINID (validate chain)
            0x20, // KECCAK256 (message hash)
            0x54, // SLOAD (check processed)
            0x15, // ISZERO
            0x57, // JUMPI (revert if replay)
            0x55, // SSTORE (mark as processed)
            0x54, // SLOAD (reentrancy lock)
            0x15, // ISZERO
            0x57, // JUMPI (revert if locked)
        ];

        let analyzer = CrossChainAnalyzer::new(bytecode);
        let vulnerabilities = analyzer.detect_vulnerabilities();

        let critical_vulns: Vec<_> = vulnerabilities
            .iter()
            .filter(|v| matches!(v.severity, SecuritySeverity::Critical))
            .collect();

        assert!(critical_vulns.is_empty());
    }
}
