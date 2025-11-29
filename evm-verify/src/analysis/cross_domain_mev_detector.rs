/// Cross-Domain MEV Detector (L1 ↔ L2)
/// Detects MEV exploitation across chains via atomic composability
/// Critical for: Optimism, Arbitrum, Base cross-chain interactions

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossDomainMEVVulnerability {
    pub vulnerability_type: CrossDomainMEVType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CrossDomainMEVType {
    L1ToL2MessageFrontrunning,     // Frontrun L1→L2 message
    L2SequencerAtomicMEV,          // L2 sequencer atomic arbitrage
    CrossRollupSandwich,           // Sandwich across L1 and L2
    ForcedInclusionExploit,        // Force L2 inclusion via L1
    WithdrawalDelayExploit,        // Exploit L2→L1 withdrawal delay
    CanonicalBridgeManipulation,   // Manipulate canonical bridge state
}

pub struct CrossDomainMEVDetector {
    bytecode: Vec<u8>,
    bridge_selectors: HashSet<[u8; 4]>,
}

impl CrossDomainMEVDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let mut bridge_selectors = HashSet::new();
        bridge_selectors.insert([0x3d, 0xce, 0x46, 0x2f]); // depositETH()
        bridge_selectors.insert([0x32, 0xb7, 0x00, 0x6c]); // withdraw()
        bridge_selectors.insert([0x8e, 0x61, 0x9e, 0x14]); // relayMessage()
        
        Self { bytecode, bridge_selectors }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CrossDomainMEVVulnerability> {
        let mut vulnerabilities = Vec::new();

        if !self.has_cross_chain_operations() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_message_frontrunning());
        vulnerabilities.extend(self.detect_atomic_mev_risk());
        vulnerabilities.extend(self.detect_withdrawal_timing_issues());

        vulnerabilities
    }

    fn detect_message_frontrunning(&self) -> Vec<CrossDomainMEVVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.is_bridge_call(i) {
                // Check if message can be frontrun on destination chain
                if !self.has_nonce_or_uniqueness(i) {
                    vulnerabilities.push(CrossDomainMEVVulnerability {
                        vulnerability_type: CrossDomainMEVType::L1ToL2MessageFrontrunning,
                        severity: SecuritySeverity::High,
                        confidence: 0.80,
                        description: "L1→L2 message vulnerable to frontrunning on L2".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. User sends L1→L2 message (swap, deposit)\n\
                            2. Message visible in L1 mempool\n\
                            3. Attacker sees and frontruns on L2\n\
                            4. Attacker transaction executes first on L2\n\
                            5. User transaction executes at worse price\n\n\
                            Fix: Use nonce/deadline or private RPC",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_atomic_mev_risk(&self) -> Vec<CrossDomainMEVVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Cross-chain swap without slippage protection
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.is_bridge_call(i) {
                // Check for price/slippage checks
                if !self.has_slippage_protection(i) {
                    vulnerabilities.push(CrossDomainMEVVulnerability {
                        vulnerability_type: CrossDomainMEVType::CrossRollupSandwich,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.75,
                        description: "Cross-chain operation without slippage protection".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. User bridges tokens + swaps on destination\n\
                            2. L2 sequencer sees intended swap\n\
                            3. Sequencer frontruns on L2 DEX\n\
                            4. User swap executes at manipulated price\n\
                            5. Sequencer backruns for profit\n\n\
                            Fix: Add minAmountOut with reasonable slippage",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_withdrawal_timing_issues(&self) -> Vec<CrossDomainMEVVulnerability> {
        let mut vulnerabilities = Vec::new();

        for i in 0..self.bytecode.len().saturating_sub(30) {
            let withdraw_selector = [0x32, 0xb7, 0x00, 0x6c];
            if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == &withdraw_selector {
                // Check for withdrawal delay handling
                if !self.has_delay_awareness(i) {
                    vulnerabilities.push(CrossDomainMEVVulnerability {
                        vulnerability_type: CrossDomainMEVType::WithdrawalDelayExploit,
                        severity: SecuritySeverity::Medium,
                        confidence: 0.70,
                        description: "L2→L1 withdrawal doesn't account for 7-day delay".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. User initiates L2→L1 withdrawal\n\
                            2. Contract expects immediate funds on L1\n\
                            3. 7-day challenge period not handled\n\
                            4. Logic breaks or funds locked\n\n\
                            Fix: Account for 7-day optimistic rollup delay",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn has_cross_chain_operations(&self) -> bool {
        for selector in &self.bridge_selectors {
            if self.bytecode.windows(4).any(|w| w == *selector) {
                return true;
            }
        }
        false
    }

    fn is_bridge_call(&self, pos: usize) -> bool {
        if pos + 4 > self.bytecode.len() {
            return false;
        }
        for selector in &self.bridge_selectors {
            if &self.bytecode[pos..pos+4] == selector {
                return true;
            }
        }
        false
    }

    fn has_nonce_or_uniqueness(&self, pos: usize) -> bool {
        for i in pos..pos.saturating_add(50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x54 { // SLOAD (nonce check)
                return true;
            }
        }
        false
    }

    fn has_slippage_protection(&self, pos: usize) -> bool {
        // Look for minAmountOut parameter (comparison)
        for i in pos..pos.saturating_add(60).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x10 || self.bytecode[i] == 0x11 { // LT or GT
                return true;
            }
        }
        false
    }

    fn has_delay_awareness(&self, pos: usize) -> bool {
        // Look for timestamp + large constant (7 days = 604800 seconds)
        for i in pos..pos.saturating_add(40).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP
                return true;
            }
        }
        false
    }
}
