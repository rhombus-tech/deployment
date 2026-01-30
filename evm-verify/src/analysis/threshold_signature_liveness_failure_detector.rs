use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSignatureLivenessVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ThresholdSignatureLivenessFailureDetector {
    bytecode: Vec<u8>,
}

impl ThresholdSignatureLivenessFailureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ThresholdSignatureLivenessVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_participant_unavailability());
        vulnerabilities.extend(self.detect_key_share_loss());
        vulnerabilities.extend(self.detect_dkg_ceremony_failure());

        vulnerabilities
    }

    fn detect_participant_unavailability(&self) -> Vec<ThresholdSignatureLivenessVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x08 { // bn256Pairing (threshold signature verification)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_threshold_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_threshold_data {
                    let has_participant_count = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_timeout = window.iter().any(|&b| b == 0x42); // TIMESTAMP
                    let has_fallback_threshold = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if has_participant_count && (!has_timeout || !has_fallback_threshold) {
                        vulns.push(ThresholdSignatureLivenessVulnerability {
                            pc,
                            vulnerability_type: "ParticipantUnavailability".to_string(),
                            description: format!(
                                "Threshold signature at PC {} requires exact participant count without fallback. If T-of-N participants \
                                unavailable, system halts. Attack: DoS T participants to freeze operations. Missing: timeout-based \
                                threshold reduction, backup participant set, emergency recovery mechanism. Should degrade gracefully \
                                when participants offline rather than complete failure.",
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

    fn detect_key_share_loss(&self) -> Vec<ThresholdSignatureLivenessVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (storing key shares)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_key_share_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_participant_id = window.iter().any(|&b| b == 0x33); // CALLER
                
                if has_key_share_data && has_participant_id {
                    let has_backup_mechanism = window.iter().any(|&b| b == 0x20); // KECCAK256 (encryption)
                    let has_share_refresh = window.iter().any(|&b| b == 0x42); // TIMESTAMP (refresh protocol)
                    let has_redundancy = window.iter().filter(|&&b| b == 0x55).count() >= 3;
                    
                    if !has_backup_mechanism && !has_share_refresh && !has_redundancy {
                        vulns.push(ThresholdSignatureLivenessVulnerability {
                            pc,
                            vulnerability_type: "KeyShareLoss".to_string(),
                            description: format!(
                                "Key share storage at PC {} without recovery mechanism. If > N-T participants lose key shares, threshold \
                                signature becomes impossible, funds permanently locked. Missing: encrypted backup shares, proactive secret \
                                sharing refresh, share recovery protocol. Single key share loss should not cause permanent system failure. \
                                Should implement periodic resharing to maintain liveness.",
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

    fn detect_dkg_ceremony_failure(&self) -> Vec<ThresholdSignatureLivenessVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x08 { // bn256Pairing (DKG verification)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_commitment = window.iter().any(|&b| b == 0x20); // KECCAK256
                let has_participant_input = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_commitment && has_participant_input {
                    let has_abort_handling = window.iter().any(|&b| b == 0x42); // TIMESTAMP (timeout)
                    let has_complaint_mechanism = window.iter().filter(|&&b| b == 0x57).count() >= 3; // Multiple paths
                    let has_restart_logic = window.iter().any(|&b| b == 0x43); // NUMBER (retry tracking)
                    
                    if !has_abort_handling || !has_complaint_mechanism || !has_restart_logic {
                        vulns.push(ThresholdSignatureLivenessVulnerability {
                            pc,
                            vulnerability_type: "DkgCeremonyFailure".to_string(),
                            description: format!(
                                "DKG ceremony at PC {} lacks failure recovery. Distributed Key Generation requires all participants; \
                                if one malicious/offline participant, ceremony fails indefinitely. Attack: single participant refuses \
                                to participate, blocks entire setup. Missing: Byzantine-tolerant DKG protocol, complaint handling, \
                                automatic restart with different participant set. Should handle up to T-1 malicious participants.",
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
