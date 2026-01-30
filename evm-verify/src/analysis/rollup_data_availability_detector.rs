use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupDataAvailabilityVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct RollupDataAvailabilityDetector {
    bytecode: Vec<u8>,
}

impl RollupDataAvailabilityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<RollupDataAvailabilityVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_data_withholding_attack());
        vulnerabilities.extend(self.detect_invalid_data_availability_proof());
        vulnerabilities.extend(self.detect_sequencer_censorship());

        vulnerabilities
    }

    fn detect_data_withholding_attack(&self) -> Vec<RollupDataAvailabilityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (state commitment)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_batch_submission = window.iter().any(|&b| b == 0x20); // KECCAK256 (batch hash)
                let has_state_root = window.iter().filter(|&&b| b == 0x35).count() >= 2;
                
                if has_batch_submission {
                    let has_data_availability_check = window.iter().filter(|&&b| b == 0x20).count() >= 3;
                    let has_calldata_verification = window.iter().any(|&b| b == 0x36); // CALLDATASIZE
                    
                    if !has_data_availability_check {
                        vulns.push(RollupDataAvailabilityVulnerability {
                            pc,
                            vulnerability_type: "DataWithholdingAttack".to_string(),
                            description: format!(
                                "Rollup batch submission at PC {} lacks data availability guarantee. Attack: sequencer posts state root commitment to L1 without publishing \
                                transaction data, users cannot reconstruct state to verify correctness or withdraw funds, sequencer can steal by withholding data proving \
                                fraud. Data availability problem. Example: optimistic rollup posts new state root, doesn't publish calldata, fraud proof window expires, \
                                invalid state finalizes. Missing: require full transaction data on L1 (calldata), data availability sampling, fraud proof data requirements. \
                                Should enforce: all transaction data published to L1 calldata (expensive but secure), or use data availability layer (Celestia/EigenDA) with \
                                proofs, or require data availability attestations from N validators.",
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

    fn detect_invalid_data_availability_proof(&self) -> Vec<RollupDataAvailabilityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (DA proof verification)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_proof_verification = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                
                if has_proof_verification {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_sampling_verification = window.iter().filter(|&&b| b == 0x02).count() >= 2; // MUL (sampling math)
                    let has_fraud_proof_check = forward.iter().any(|&b| b == 0x14); // EQ
                    
                    if !has_sampling_verification {
                        vulns.push(RollupDataAvailabilityVulnerability {
                            pc,
                            vulnerability_type: "InvalidDataAvailabilityProof".to_string(),
                            description: format!(
                                "Data availability proof verification at PC {} insufficient. Attack: rollup uses DA sampling or committee attestations, attacker provides \
                                invalid DA proof (e.g., samples that don't represent full data, or forged committee signatures), batch accepted without actual data availability, \
                                users cannot reconstruct state. Missing: proper DAS (Data Availability Sampling) verification, KZG commitment verification, committee signature \
                                validation with sufficient threshold. Should implement: verify KZG proofs for data chunks, require >66% committee signatures, or use erasure \
                                coding with random sampling verification.",
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

    fn detect_sequencer_censorship(&self) -> Vec<RollupDataAvailabilityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (transaction inclusion)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_sequencer_role = window.iter().any(|&b| b == 0x33); // CALLER
                let has_batch_building = window.iter().any(|&b| b == 0x20); // KECCAK256
                
                if has_sequencer_role && has_batch_building {
                    let has_forced_inclusion = window.iter().filter(|&&b| b == 0x42).count() >= 2; // TIMESTAMP delays
                    let has_censorship_resistance = window.iter().any(|&b| b == 0xF1); // CALL (force include)
                    
                    if !has_forced_inclusion {
                        vulns.push(RollupDataAvailabilityVulnerability {
                            pc,
                            vulnerability_type: "SequencerCensorship".to_string(),
                            description: format!(
                                "Rollup sequencing at PC {} lacks censorship resistance. Attack: centralized sequencer can censor user transactions indefinitely, user tries \
                                to withdraw from rollup, sequencer refuses to include withdrawal transaction, user funds stuck. Censorship attack. Example: Arbitrum/Optimism \
                                sequencer controlled by single entity, can selectively censor addresses. Missing: forced inclusion mechanism (users can submit txs directly to L1), \
                                sequencer rotation, decentralized sequencer set. Should implement: if sequencer doesn't include tx within 24h, user can force-include via L1 \
                                transaction, or use shared sequencer (Espresso), or implement sequencer slashing for censorship.",
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
