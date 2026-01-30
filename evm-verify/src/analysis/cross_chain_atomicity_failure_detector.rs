use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossChainAtomicityVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CrossChainAtomicityFailureDetector {
    bytecode: Vec<u8>,
}

impl CrossChainAtomicityFailureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CrossChainAtomicityVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_missing_rollback_mechanism());
        vulnerabilities.extend(self.detect_partial_state_commitment());
        vulnerabilities.extend(self.detect_timeout_handling_failure());

        vulnerabilities
    }

    fn detect_missing_rollback_mechanism(&self) -> Vec<CrossChainAtomicityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (committing cross-chain operation)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_remote_call = window.iter().any(|&b| matches!(b, 0xF1 | 0xFA)); // Cross-chain message
                let has_state_change = window.iter().filter(|&&b| b == 0x55).count() >= 1;
                
                if has_remote_call && has_state_change {
                    let has_rollback_path = window.iter().filter(|&&b| b == 0x57).count() >= 3; // Multiple JUMPI
                    let has_revert_data = window.iter().any(|&b| b == 0xFD); // REVERT
                    
                    if !has_rollback_path || !has_revert_data {
                        vulns.push(CrossChainAtomicityVulnerability {
                            pc,
                            vulnerability_type: "MissingRollbackMechanism".to_string(),
                            description: format!(
                                "Cross-chain operation at PC {} commits state without rollback. If remote chain operation fails, local \
                                state already changed. Attack: trigger cross-chain swap, local chain locks tokens, remote chain fails, \
                                tokens locked permanently. Missing: two-phase commit, compensating transactions, timeout-based rollback. \
                                Atomicity requires ability to undo local changes if remote fails.",
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

    fn detect_partial_state_commitment(&self) -> Vec<CrossChainAtomicityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF1 | 0xFA) { // External call for cross-chain
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_pre_state_changes = window.iter().filter(|&&b| b == 0x55).count() >= 1; // SSTORE before call
                
                if has_pre_state_changes {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_success_check = forward.iter().any(|&b| b == 0x15); // ISZERO (checking return value)
                    let has_revert_on_fail = forward.iter().any(|&b| b == 0xFD); // REVERT
                    
                    if !has_success_check || !has_revert_on_fail {
                        vulns.push(CrossChainAtomicityVulnerability {
                            pc,
                            vulnerability_type: "PartialStateCommitment".to_string(),
                            description: format!(
                                "Cross-chain call at PC {} preceded by state changes without failure handling. State committed before \
                                knowing if remote operation succeeds. Attack: local state changes persist even when cross-chain message \
                                fails to deliver. Missing: defer state changes until confirmation, check call success, revert on failure. \
                                Creates inconsistent state across chains.",
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

    fn detect_timeout_handling_failure(&self) -> Vec<CrossChainAtomicityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP (timeout check)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_pending_op = window.iter().any(|&b| b == 0x54); // SLOAD (pending cross-chain op)
                
                if has_pending_op {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_timeout_handling = forward.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if has_timeout_handling {
                        let has_refund_logic = forward.iter().any(|&b| matches!(b, 0xF1 | 0x55)); // CALL or SSTORE (refund)
                        let has_cleanup = forward.iter().filter(|&&b| b == 0x55).count() >= 2;
                        
                        if !has_refund_logic || !has_cleanup {
                            vulns.push(CrossChainAtomicityVulnerability {
                                pc,
                                vulnerability_type: "TimeoutHandlingFailure".to_string(),
                                description: format!(
                                    "Timeout check at PC {} without proper failure handling. Cross-chain operation times out but no cleanup. \
                                    Attack: remote chain congested, message never arrives, local funds locked forever. Missing: timeout refund \
                                    mechanism, state cleanup, user notification. After timeout, should automatically refund user and clear \
                                    pending state. Without timeout handling, cross-chain failures cause permanent fund loss.",
                                    pc
                                ),
                                confidence: 0.85,
                            });
                        }
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
