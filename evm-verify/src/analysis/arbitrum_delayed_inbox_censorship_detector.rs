use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArbitrumInboxVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ArbitrumDelayedInboxCensorshipDetector {
    bytecode: Vec<u8>,
}

impl ArbitrumDelayedInboxCensorshipDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ArbitrumInboxVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_sequencer_bypass_blocking());
        vulnerabilities.extend(self.detect_forced_inclusion_delay_attack());
        vulnerabilities.extend(self.detect_delayed_message_ordering_manipulation());

        vulnerabilities
    }

    fn detect_sequencer_bypass_blocking(&self) -> Vec<ArbitrumInboxVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x33 { // CALLER (checking message source)
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_address_check = window.iter().any(|&b| b == 0x14); // EQ (sequencer address)
                let has_revert = window.iter().any(|&b| b == 0xFD); // REVERT
                
                if has_address_check && has_revert {
                    let start = if pc > 60 { pc - 60 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_delayed_inbox_check = pre_window.iter().any(|&b| b == 0x54); // SLOAD (delayed inbox flag)
                    let has_force_inclusion = window.iter().any(|&b| b == 0x43); // NUMBER (delay period)
                    
                    if !has_delayed_inbox_check || !has_force_inclusion {
                        vulns.push(ArbitrumInboxVulnerability {
                            pc,
                            vulnerability_type: "SequencerBypassBlocking".to_string(),
                            description: format!(
                                "Caller restriction at PC {} blocks delayed inbox bypass. Arbitrum's censorship resistance relies \
                                on users submitting to delayed inbox if sequencer censors. Contract only accepting sequencer messages \
                                defeats this. Missing: delayed inbox message acceptance, force-inclusion mechanism. Users cannot \
                                bypass malicious sequencer, violating Arbitrum's trust-minimization design.",
                                pc
                            ),
                            confidence: 0.89,
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

    fn detect_forced_inclusion_delay_attack(&self) -> Vec<ArbitrumInboxVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x43 { // NUMBER (block number for delay)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_message_timestamp = window.iter().any(|&b| b == 0x54); // SLOAD (message submission)
                
                if has_message_timestamp {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_minimum_delay = forward.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_maximum_delay = forward.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if has_minimum_delay && !has_maximum_delay {
                        vulns.push(ArbitrumInboxVulnerability {
                            pc,
                            vulnerability_type: "ForcedInclusionDelayAttack".to_string(),
                            description: format!(
                                "Delayed inbox at PC {} enforces minimum delay without maximum. Sequencer can delay forced \
                                inclusions indefinitely while processing own messages immediately. Attack: extend delay period each \
                                block, never process user's delayed message. Missing: maximum delay enforcement (e.g., 24 hours), \
                                automatic inclusion after timeout. Enables indefinite censorship despite delayed inbox existence.",
                                pc
                            ),
                            confidence: 0.87,
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

    fn detect_delayed_message_ordering_manipulation(&self) -> Vec<ArbitrumInboxVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (processing delayed message)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_message_index = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_message_index {
                    let has_sequential_enforcement = window.iter().any(|&b| b == 0x14); // EQ (checking next index)
                    let has_gap_detection = window.iter().filter(|&&b| b == 0x54).count() >= 2; // Multiple SLOAD
                    
                    if !has_sequential_enforcement || !has_gap_detection {
                        vulns.push(ArbitrumInboxVulnerability {
                            pc,
                            vulnerability_type: "DelayedMessageOrderingManipulation".to_string(),
                            description: format!(
                                "Delayed message processing at PC {} without ordering enforcement. Sequencer can reorder delayed \
                                inbox messages for MEV extraction. Attack: observe profitable arbitrage in message N, process message \
                                N+1 first to frontrun. Missing: sequential message index validation, gap prevention, deterministic \
                                ordering. Delayed inbox should process in strict FIFO order to prevent sequencer manipulation.",
                                pc
                            ),
                            confidence: 0.85,
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
