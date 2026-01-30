use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SMPCVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct SecureMultipartyComputationDetector {
    bytecode: Vec<u8>,
}

impl SecureMultipartyComputationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }

    pub fn detect_vulnerabilities(&self) -> Vec<SMPCVulnerability> {
        let mut vulns = Vec::new();

        vulns.extend(self.detect_missing_abort_protection());
        vulns.extend(self.detect_unfair_output_delivery());
        vulns.extend(self.detect_missing_commitments());

        vulns
    }

    fn detect_missing_abort_protection(&self) -> Vec<SMPCVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // External call to participant
            if opcode == 0xF1 || opcode == 0xF4 {
                let start = if pc > 80 { pc - 80 } else { 0 };
                let window_end = (pc + 80).min(self.bytecode.len());
                
                // Check for commit-reveal pattern (KECCAK256 before and after call)
                let has_commit = self.bytecode[start..pc].iter().any(|&b| b == 0x20);
                let has_reveal = self.bytecode[(pc + 1)..window_end].iter().any(|&b| b == 0x20);
                
                // Check for timeout mechanism (TIMESTAMP comparison)
                let has_timeout = self.bytecode[start..window_end].iter().any(|&b| b == 0x42);
                
                if !has_commit || !has_reveal || !has_timeout {
                    vulns.push(SMPCVulnerability {
                        pc,
                        vulnerability_type: "MissingAbortProtection".to_string(),
                        description: format!(
                            "MPC participant call at PC {} without abort protection. Malicious participant can: \
                            (1) See others' inputs before committing, (2) Abort selectively after learning result, \
                            (3) Gain unfair advantage. Implement: (1) Commit-reveal for all inputs, \
                            (2) Timeout for non-responsive parties, (3) Compensation for aborts.",
                            pc
                        ),
                        confidence: 0.75,
                    });
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_unfair_output_delivery(&self) -> Vec<SMPCVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // SSTORE (storing MPC result)
            if opcode == 0x55 {
                let start = if pc > 100 { pc - 100 } else { 0 };
                
                // Check if result comes from computation (has arithmetic ops)
                let has_computation = self.bytecode[start..pc].iter()
                    .any(|&b| matches!(b, 0x01 | 0x02 | 0x03 | 0x04)); // ADD, MUL, SUB, DIV
                
                // Check for simultaneous reveal (multiple CALLs or all participants)
                let call_count = self.bytecode[start..pc].iter().filter(|&&b| b == 0xF1).count();
                
                // Check for fairness enforcement (all get result or none do)
                let window_end = (pc + 50).min(self.bytecode.len());
                let has_revert_on_failure = self.bytecode[(pc + 1)..window_end].iter().any(|&b| b == 0xFD);
                
                if has_computation && call_count >= 1 && !has_revert_on_failure {
                    vulns.push(SMPCVulnerability {
                        pc,
                        vulnerability_type: "UnfairOutputDelivery".to_string(),
                        description: format!(
                            "MPC result stored at PC {} without fairness guarantee. First participant to receive \
                            output can abort, preventing others from getting result while keeping their own. \
                            Use gradual release or blockchain-enforced simultaneous reveal to ensure fairness.",
                            pc
                        ),
                        confidence: 0.70,
                    });
                }
            }
            
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_missing_commitments(&self) -> Vec<SMPCVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // CALLDATALOAD (receiving participant input)
            if opcode == 0x35 {
                let window_end = (pc + 60).min(self.bytecode.len());
                
                // Check if input is hashed (committed)
                let has_hash = self.bytecode[(pc + 1)..window_end].iter().any(|&b| b == 0x20);
                
                // Check if commitment is stored before reveal
                let has_sstore_before_use = self.bytecode[(pc + 1)..window_end].windows(30).any(|w| {
                    let has_store = w.iter().any(|&b| b == 0x55);
                    let has_computation = w.iter().any(|&b| matches!(b, 0x01 | 0x02));
                    has_store && !has_computation
                });
                
                if !has_hash || !has_sstore_before_use {
                    vulns.push(SMPCVulnerability {
                        pc,
                        vulnerability_type: "MissingCommitment".to_string(),
                        description: format!(
                            "MPC input at PC {} without commitment phase. Participants can see others' inputs \
                            before revealing their own, enabling: (1) Input manipulation based on others' values, \
                            (2) Strategic aborting, (3) Fairness violations. Use two-phase: commit hash(input, nonce), \
                            then reveal input+nonce.",
                            pc
                        ),
                        confidence: 0.80,
                    });
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
