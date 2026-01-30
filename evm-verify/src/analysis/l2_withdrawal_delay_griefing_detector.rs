use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalDelayVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct L2WithdrawalDelayGriefingDetector {
    bytecode: Vec<u8>,
}

impl L2WithdrawalDelayGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<WithdrawalDelayVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unbounded_challenge_period());
        vulnerabilities.extend(self.detect_withdrawal_queue_dos());
        vulnerabilities.extend(self.detect_finalization_front_running());

        vulnerabilities
    }

    fn detect_unbounded_challenge_period(&self) -> Vec<WithdrawalDelayVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP (withdrawal delay)
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_withdrawal_request = window.iter().any(|&b| b == 0x54); // SLOAD
                
                if has_withdrawal_request {
                    let window_end = (pc + 60).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_delay_check = forward.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    
                    if has_delay_check {
                        let has_maximum_delay = forward.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                        let has_emergency_exit = forward.iter().any(|&b| b == 0x57); // JUMPI (fallback path)
                        
                        if !has_maximum_delay || !has_emergency_exit {
                            vulns.push(WithdrawalDelayVulnerability {
                                pc,
                                vulnerability_type: "UnboundedChallengePeriod".to_string(),
                                description: format!(
                                    "Withdrawal delay at PC {} without maximum bound. Optimistic rollup challenge periods can be extended \
                                    indefinitely by malicious actors submitting invalid fraud proofs. Attack: initiate withdrawal, adversary \
                                    continuously challenges with false proofs, user funds locked forever. Missing: maximum challenge period \
                                    (e.g., 7 days fixed), challenge bond slashing, emergency withdrawal after timeout. Enables permanent fund locking.",
                                    pc
                                ),
                                confidence: 0.88,
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

    fn detect_withdrawal_queue_dos(&self) -> Vec<WithdrawalDelayVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (queueing withdrawal)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_queue_addition = window.iter().any(|&b| b == 0x01); // ADD (incrementing queue)
                
                if has_queue_addition {
                    let has_queue_limit = window.iter().any(|&b| matches!(b, 0x10 | 0x11)); // LT, GT
                    let has_priority_system = window.iter().any(|&b| b == 0x02); // MUL (priority calculation)
                    
                    if !has_queue_limit && !has_priority_system {
                        vulns.push(WithdrawalDelayVulnerability {
                            pc,
                            vulnerability_type: "WithdrawalQueueDos".to_string(),
                            description: format!(
                                "Withdrawal queue at PC {} unbounded, enabling DoS. Attack: submit thousands of tiny withdrawal requests, \
                                fill queue, block legitimate withdrawals. Processing queue becomes prohibitively expensive. Missing: maximum \
                                queue size, minimum withdrawal amount, priority-based processing. Griefing attack prevents users from \
                                withdrawing funds back to L1.",
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

    fn detect_finalization_front_running(&self) -> Vec<WithdrawalDelayVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if matches!(opcode, 0xF1 | 0xF4) { // CALL, DELEGATECALL (finalizing withdrawal)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_withdrawal_id = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_value_transfer = window.iter().any(|&b| b == 0x34); // CALLVALUE
                
                if has_withdrawal_id || has_value_transfer {
                    let has_recipient_validation = window.iter().any(|&b| b == 0x33); // CALLER
                    let has_commitment = window.iter().any(|&b| b == 0x20); // KECCAK256
                    
                    if !has_recipient_validation || !has_commitment {
                        vulns.push(WithdrawalDelayVulnerability {
                            pc,
                            vulnerability_type: "FinalizationFrontRunning".to_string(),
                            description: format!(
                                "Withdrawal finalization at PC {} allows front-running. Attack: observe pending finalization transaction \
                                in mempool, frontrun with own finalization to different address. Withdrawal parameters not committed at \
                                request time. Missing: recipient address commitment in initial request, withdrawal immutability, recipient-only \
                                finalization. User initiates withdrawal to address A, attacker finalizes to address B.",
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
