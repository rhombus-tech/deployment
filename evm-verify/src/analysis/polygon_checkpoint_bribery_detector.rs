use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolygonCheckpointVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct PolygonCheckpointBriberyDetector {
    bytecode: Vec<u8>,
}

impl PolygonCheckpointBriberyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<PolygonCheckpointVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_validator_collusion_incentive());
        vulnerabilities.extend(self.detect_checkpoint_delay_attack());
        vulnerabilities.extend(self.detect_state_sync_manipulation());

        vulnerabilities
    }

    fn detect_validator_collusion_incentive(&self) -> Vec<PolygonCheckpointVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF1 | 0xF4) { // CALL, DELEGATECALL (validator reward)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_value_transfer = window.iter().any(|&b| b == 0x34); // CALLVALUE
                let has_checkpoint_data = window.iter().any(|&b| b == 0x54); // SLOAD
                
                if has_value_transfer || has_checkpoint_data {
                    let has_slashing = window.iter().any(|&b| b == 0x03); // SUB (penalty)
                    let has_consensus_check = window.iter().filter(|&&b| b == 0x14).count() >= 2; // Multiple EQ
                    let has_finality_delay = window.iter().any(|&b| b == 0x43); // NUMBER
                    
                    if !has_slashing || !has_consensus_check || !has_finality_delay {
                        vulns.push(PolygonCheckpointVulnerability {
                            pc,
                            vulnerability_type: "ValidatorCollusionIncentive".to_string(),
                            description: format!(
                                "Validator interaction at PC {} creates bribery opportunity. Protocol relies on Polygon validators \
                                checkpointing state to Ethereum. Attack: bribe validators to delay/censor specific checkpoints, or \
                                collude to checkpoint invalid state. Missing: economic penalty for malicious checkpoints, multi-round \
                                consensus verification, challenge period. Enables checkpoint manipulation through validator coordination.",
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

    fn detect_checkpoint_delay_attack(&self) -> Vec<PolygonCheckpointVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x43 { // NUMBER (block number for checkpoint timing)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_checkpoint_ref = window.iter().any(|&b| b == 0x54); // SLOAD (last checkpoint)
                
                if has_checkpoint_ref {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_maximum_delay = forward.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_timeout_fallback = forward.iter().filter(|&&b| b == 0x57).count() >= 2; // Multiple JUMPI
                    
                    if !has_maximum_delay || !has_timeout_fallback {
                        vulns.push(PolygonCheckpointVulnerability {
                            pc,
                            vulnerability_type: "CheckpointDelayAttack".to_string(),
                            description: format!(
                                "Checkpoint timing at PC {} without delay bounds. Validators can delay checkpointing to L1, \
                                leaving Polygon state uncommitted. Attack: delay checkpoint submission to prevent finality, enabling \
                                double-spend or state reversion. Missing: maximum checkpoint interval, automatic checkpoint trigger, \
                                delay penalty. Users relying on checkpoint finality vulnerable to delayed confirmation attacks.",
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

    fn detect_state_sync_manipulation(&self) -> Vec<PolygonCheckpointVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (syncing state from L1)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_external_data = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_external_data {
                    let has_merkle_proof = window.iter().any(|&b| b == 0x20); // KECCAK256
                    let has_checkpoint_verification = window.iter().filter(|&&b| b == 0x14).count() >= 2; // Multiple EQ
                    let has_state_root_check = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                    
                    if !has_merkle_proof || !has_checkpoint_verification || !has_state_root_check {
                        vulns.push(PolygonCheckpointVulnerability {
                            pc,
                            vulnerability_type: "StateSyncManipulation".to_string(),
                            description: format!(
                                "State sync at PC {} trusts Polygon checkpoint without full verification. State bridge from L1→Polygon \
                                relies on checkpoint integrity. Attack: if validators checkpoint invalid state, contract syncs corrupted \
                                data. Missing: Merkle proof verification, state root validation against L1, checkpoint signature checks. \
                                Enables state corruption through malicious checkpoint acceptance.",
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
