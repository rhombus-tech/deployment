use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreimageTimingVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct AtomicSwapPreimageRevelationTimingDetector {
    bytecode: Vec<u8>,
}

impl AtomicSwapPreimageRevelationTimingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<PreimageTimingVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_early_preimage_exposure());
        vulnerabilities.extend(self.detect_missing_atomicity_window());
        vulnerabilities.extend(self.detect_frontrunnable_preimage());

        vulnerabilities
    }

    fn detect_early_preimage_exposure(&self) -> Vec<PreimageTimingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for KECCAK256 hash verification
            if opcode == 0x20 {
                let window_end = (pc + 50).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check for hash comparison (EQ)
                let has_hash_check = window.iter().any(|&b| b == 0x14);
                
                if has_hash_check {
                    // Look for LOG operations that might expose preimage
                    let has_log = window.iter().any(|&b| matches!(b, 0xA0 | 0xA1 | 0xA2 | 0xA3 | 0xA4));
                    
                    // Check if SSTORE happens before transfer
                    let mut sstore_before_call = false;
                    for i in 0..window.len() - 1 {
                        if window[i] == 0x55 { // SSTORE
                            // Check if CALL/DELEGATECALL comes after
                            if window[i + 1..].iter().any(|&b| matches!(b, 0xF1 | 0xF4)) {
                                sstore_before_call = true;
                                break;
                            }
                        }
                    }
                    
                    if has_log || sstore_before_call {
                        vulns.push(PreimageTimingVulnerability {
                            pc,
                            vulnerability_type: "EarlyPreimageExposure".to_string(),
                            description: format!(
                                "Preimage exposed early at PC {} via event emission or storage before cross-chain \
                                confirmation. Enables race condition: attacker monitors chain A for preimage, \
                                frontruns claim on chain B with revealed secret, steals funds from both chains. \
                                Breaks atomic swap atomicity guarantee.",
                                pc
                            ),
                            confidence: 0.91,
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

    fn detect_missing_atomicity_window(&self) -> Vec<PreimageTimingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for preimage verification followed by transfer
            if opcode == 0x20 { // KECCAK256
                let window_end = (pc + 60).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_eq = window.iter().any(|&b| b == 0x14);
                let has_transfer = window.iter().any(|&b| matches!(b, 0xF1 | 0xF0)); // CALL, CREATE
                
                if has_eq && has_transfer {
                    // Check for cross-chain confirmation mechanism
                    // Look for external calls that might verify other chain state
                    let start = if pc > 100 { pc - 100 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    // Missing: oracle call, message verification, or state proof
                    let has_oracle_call = pre_window.iter().any(|&b| b == 0xFA); // STATICCALL
                    let has_signature_check = pre_window.iter().any(|&b| b == 0x01); // ECRECOVER precompile
                    
                    if !has_oracle_call && !has_signature_check {
                        vulns.push(PreimageTimingVulnerability {
                            pc,
                            vulnerability_type: "MissingAtomicityWindow".to_string(),
                            description: format!(
                                "Atomic swap claim at PC {} lacks cross-chain atomicity verification. \
                                Missing mechanisms: oracle-based confirmation of counterparty chain state, \
                                cryptographic proof of swap completion, time-bounded atomicity window. \
                                Allows partial execution where one party claims without guaranteeing other party's claim.",
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

    fn detect_frontrunnable_preimage(&self) -> Vec<PreimageTimingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            // Look for CALLDATALOAD (reading preimage from calldata)
            if opcode == 0x35 {
                let window_end = (pc + 40).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                // Check if preimage goes through KECCAK256 verification
                let has_keccak = window.iter().any(|&b| b == 0x20);
                
                if has_keccak {
                    // Look for frontrun protection mechanisms
                    // Check for: msg.sender validation, commit-reveal, or time delays
                    let start = if pc > 50 { pc - 50 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let has_caller_check = pre_window.iter().any(|&b| b == 0x33); // CALLER
                    let has_origin_check = pre_window.iter().any(|&b| b == 0x32); // ORIGIN
                    let has_timestamp_delay = pre_window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    
                    if !has_caller_check && !has_origin_check && !has_timestamp_delay {
                        vulns.push(PreimageTimingVulnerability {
                            pc,
                            vulnerability_type: "FrontrunablePreimage".to_string(),
                            description: format!(
                                "Preimage revelation at PC {} is frontrunnable. No protection against: \
                                mempool monitoring, transaction replication with higher gas, preimage theft \
                                by MEV bots. Attacker can: observe pending claim transaction, extract preimage \
                                from calldata, submit competing transaction, claim funds before original sender.",
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
}
