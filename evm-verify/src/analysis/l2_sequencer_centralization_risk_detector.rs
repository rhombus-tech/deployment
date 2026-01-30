use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerCentralizationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct L2SequencerCentralizationRiskDetector {
    bytecode: Vec<u8>,
}

impl L2SequencerCentralizationRiskDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SequencerCentralizationVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_single_sequencer_dependency());
        vulnerabilities.extend(self.detect_censorship_resistance_bypass());
        vulnerabilities.extend(self.detect_mev_extraction_centralization());

        vulnerabilities
    }

    fn detect_single_sequencer_dependency(&self) -> Vec<SequencerCentralizationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x33 { // CALLER (checking sequencer)
                let window_end = (pc + 60).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_address_check = window.iter().any(|&b| b == 0x14); // EQ
                let has_revert = window.iter().any(|&b| b == 0xFD); // REVERT
                
                if has_address_check && has_revert {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_fallback_sequencer = pre_window.iter().filter(|&&b| b == 0x14).count() >= 2;
                    let has_decentralized_submission = pre_window.iter().any(|&b| b == 0x43); // NUMBER (force inclusion)
                    
                    if !has_fallback_sequencer && !has_decentralized_submission {
                        vulns.push(SequencerCentralizationVulnerability {
                            pc,
                            vulnerability_type: "SingleSequencerDependency".to_string(),
                            description: format!(
                                "Transaction processing at PC {} requires specific sequencer. Single point of failure: if sequencer \
                                goes offline, L2 halts entirely. Attack: sequencer operator can censor transactions, extract MEV, \
                                or demand ransom. Missing: multiple sequencer support, permissionless transaction submission, \
                                forced inclusion mechanism. L2 should allow users to bypass unresponsive/malicious sequencer.",
                                pc
                            ),
                            confidence: 0.88,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_censorship_resistance_bypass(&self) -> Vec<SequencerCentralizationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (transaction inclusion)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_tx_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_tx_data {
                    let has_l1_fallback = window.iter().any(|&b| matches!(b, 0xF1 | 0xFA)); // L1 contract call
                    let has_delay_period = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let has_escape_hatch = window.iter().filter(|&&b| b == 0x57).count() >= 2; // Multiple JUMPI
                    
                    if !has_l1_fallback || !has_delay_period || !has_escape_hatch {
                        vulns.push(SequencerCentralizationVulnerability {
                            pc,
                            vulnerability_type: "CensorshipResistanceBypass".to_string(),
                            description: format!(
                                "Transaction inclusion at PC {} controlled solely by sequencer. No censorship resistance: sequencer \
                                can indefinitely exclude specific users/transactions. Attack: blacklist addresses, censor DeFi \
                                competitors, demand bribes for inclusion. Missing: L1 escape hatch (submit to L1 after delay), \
                                forced inclusion queue, decentralized sequencer set. Users should be able to bypass censorship.",
                                pc
                            ),
                            confidence: 0.86,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_mev_extraction_centralization(&self) -> Vec<SequencerCentralizationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x43 { // NUMBER (transaction ordering)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_tx_ordering = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_tx_ordering {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_fair_ordering = forward.iter().any(|&b| b == 0x42); // TIMESTAMP (FIFO)
                    let has_mev_redistribution = forward.iter().any(|&b| matches!(b, 0xF1 | 0x55)); // Payment to users
                    let has_private_pool_protection = forward.iter().any(|&b| b == 0x20); // KECCAK256 (commit-reveal)
                    
                    if !has_fair_ordering && !has_mev_redistribution && !has_private_pool_protection {
                        vulns.push(SequencerCentralizationVulnerability {
                            pc,
                            vulnerability_type: "MevExtractionCentralization".to_string(),
                            description: format!(
                                "Transaction ordering at PC {} allows sequencer MEV extraction. Sequencer can frontrun, backrun, \
                                sandwich users with zero cost. Attack: see pending swaps, insert own transactions for profit, \
                                extract all MEV value. Missing: fair ordering (FIFO/encrypted mempool), MEV redistribution to users, \
                                batch auctions. Centralized sequencer = centralized MEV extraction, taxing all L2 users.",
                                pc
                            ),
                            confidence: 0.84,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }
}
