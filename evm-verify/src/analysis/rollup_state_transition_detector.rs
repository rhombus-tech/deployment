use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RollupStateTransitionVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct RollupStateTransitionDetector {
    bytecode: Vec<u8>,
}

impl RollupStateTransitionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<RollupStateTransitionVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_invalid_state_transition());
        vulnerabilities.extend(self.detect_state_root_manipulation());
        vulnerabilities.extend(self.detect_batch_ordering_violation());

        vulnerabilities
    }

    fn detect_invalid_state_transition(&self) -> Vec<RollupStateTransitionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (state root update)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_new_state_root = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_old_state_root = window.iter().any(|&b| b == 0x54); // SLOAD
                
                if has_new_state_root {
                    let has_transition_validation = window.iter().filter(|&&b| b == 0x20).count() >= 2; // KECCAK256
                    let has_proof_verification = window.iter().any(|&b| b == 0xFA); // STATICCALL (verifier)
                    
                    if !has_transition_validation && !has_proof_verification {
                        vulns.push(RollupStateTransitionVulnerability {
                            pc,
                            vulnerability_type: "InvalidStateTransition".to_string(),
                            description: format!(
                                "State root update at PC {} without transition validity check. Attack: rollup accepts new state root without verifying it's valid successor to \
                                previous state, attacker submits arbitrary state root, if not caught by fraud proofs (optimistic) or proof verification (ZK), can finalize \
                                invalid state. Missing: state transition function validation, parent state root verification, sequential batch numbering. Should enforce: \
                                require(newRoot == computeNextRoot(oldRoot, batchData), 'Invalid state transition'), verify batch number increments by 1, check parent hash \
                                matches previous batch.",
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

    fn detect_state_root_manipulation(&self) -> Vec<RollupStateTransitionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (state root storage)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_admin_role = window.iter().any(|&b| b == 0x33); // CALLER
                let has_state_modification = window.iter().filter(|&&b| b == 0x55).count() >= 2;
                
                if has_admin_role && has_state_modification {
                    let has_governance_delay = window.iter().filter(|&&b| b == 0x42).count() >= 2; // TIMESTAMP
                    let has_proof_requirement = window.iter().any(|&b| b == 0xFA); // STATICCALL
                    
                    if !has_governance_delay && !has_proof_requirement {
                        vulns.push(RollupStateTransitionVulnerability {
                            pc,
                            vulnerability_type: "StateRootManipulation".to_string(),
                            description: format!(
                                "State root modification at PC {} allows admin override. Attack: rollup operator has ability to directly modify state root without proof, \
                                operator can insert fraudulent state, bypass normal verification mechanisms, steal user funds. Centralization risk. Example: zkSync/Optimism \
                                admin function allows emergency state root update, malicious admin sets state root showing their address owns all funds. Missing: remove admin \
                                state override, or require multi-sig + time delay, or require proof even for admin. Should implement: remove privileged state modification \
                                entirely, or require 7-day timelock + 3-of-5 multisig for emergency state updates.",
                                pc
                            ),
                            confidence: 0.90,
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

    fn detect_batch_ordering_violation(&self) -> Vec<RollupStateTransitionVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (batch submission)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_batch_number = window.iter().filter(|&&b| b == 0x35).count() >= 2;
                
                if has_batch_number {
                    let has_sequential_check = window.iter().filter(|&&b| b == 0x01).count() >= 1; // ADD (increment)
                    let has_ordering_validation = window.iter().filter(|&&b| b == 0x14).count() >= 2; // EQ checks
                    
                    if !has_sequential_check || !has_ordering_validation {
                        vulns.push(RollupStateTransitionVulnerability {
                            pc,
                            vulnerability_type: "BatchOrderingViolation".to_string(),
                            description: format!(
                                "Batch submission at PC {} doesn't enforce sequential ordering. Attack: rollup allows batches to be submitted out of order, attacker submits \
                                batch N+2 before batch N+1, causes state inconsistency, can exploit by cherry-picking which state transitions to include. Missing: strict batch \
                                number sequence validation, parent batch hash verification, timestamp ordering checks. Should enforce: require(batchNumber == lastBatchNumber + 1, \
                                'Non-sequential batch'), require(parentBatchHash == batches[batchNumber - 1].hash, 'Invalid parent'), require(timestamp > lastBatchTimestamp, \
                                'Timestamp ordering violation').",
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
