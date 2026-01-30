use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationSystemVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct ReputationSystemDetector {
    bytecode: Vec<u8>,
}

impl ReputationSystemDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ReputationSystemVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_unchecked_score_updates());
        vulnerabilities.extend(self.detect_self_reputation_boost());
        vulnerabilities.extend(self.detect_reputation_decay_bypass());

        vulnerabilities
    }

    fn detect_unchecked_score_updates(&self) -> Vec<ReputationSystemVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // SSTORE updating reputation
            if opcode == 0x55 {
                let start = if pc > 80 { pc - 80 } else { 0 };
                
                // Check for arithmetic ops (score modification)
                let has_arithmetic = self.bytecode[start..pc].iter()
                    .any(|&b| matches!(b, 0x01 | 0x02 | 0x03)); // ADD, MUL, SUB
                
                // Check for validation (comparison before update)
                let has_validation = self.bytecode[start..pc].iter()
                    .any(|&b| matches!(b, 0x10 | 0x11 | 0x12)); // LT, GT, SLT
                
                // Check for overflow protection (newer Solidity has built-in)
                let has_overflow_check = self.bytecode[start..pc].iter().any(|&b| b == 0x57); // JUMPI
                
                if has_arithmetic && !has_validation && !has_overflow_check {
                    vulns.push(ReputationSystemVulnerability {
                        pc,
                        vulnerability_type: "UncheckedScoreUpdate".to_string(),
                        description: format!(
                            "Reputation score modified at PC {} without bounds checking. Enables: \
                            (1) Integer overflow to max reputation, (2) Underflow to wrap around, \
                            (3) Unrealistic score manipulation. Add require(newScore < MAX_SCORE) validation.",
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

    fn detect_self_reputation_boost(&self) -> Vec<ReputationSystemVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // SSTORE (reputation update)
            if opcode == 0x55 {
                let start = if pc > 100 { pc - 100 } else { 0 };
                
                // Check if uses CALLER address
                let has_caller = self.bytecode[start..pc].iter().any(|&b| b == 0x33);
                
                // Check if positive modification (ADD or MUL)
                let has_increase = self.bytecode[start..pc].iter().any(|&b| b == 0x01 || b == 0x02);
                
                // Check for other party verification (need two different addresses)
                let caller_count = self.bytecode[start..pc].iter().filter(|&&b| b == 0x33).count();
                let calldataload_count = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count();
                
                if has_caller && has_increase && (caller_count < 2 && calldataload_count == 0) {
                    vulns.push(ReputationSystemVulnerability {
                        pc,
                        vulnerability_type: "SelfReputationBoost".to_string(),
                        description: format!(
                            "Reputation update at PC {} allows self-boosting. User can increase their own \
                            reputation without external validation. Attacker: (1) Calls repeatedly to max reputation, \
                            (2) Games system for privileges, (3) Bypasses trust mechanisms. Require other party \
                            to grant reputation.",
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

    fn detect_reputation_decay_bypass(&self) -> Vec<ReputationSystemVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // SSTORE reputation storage
            if opcode == 0x55 {
                let start = if pc > 60 { pc - 60 } else { 0 };
                
                // Check for timestamp-based decay
                let has_timestamp = self.bytecode[start..pc].iter().any(|&b| b == 0x42);
                
                // Check for arithmetic that would implement decay (SUB, DIV)
                let has_decay_math = self.bytecode[start..pc].iter().any(|&b| b == 0x03 || b == 0x04);
                
                // Reputation systems should have time-based decay
                if !has_timestamp && !has_decay_math {
                    let has_sload = self.bytecode[start..pc].iter().any(|&b| b == 0x54);
                    if has_sload {
                        vulns.push(ReputationSystemVulnerability {
                            pc,
                            vulnerability_type: "NoReputationDecay".to_string(),
                            description: format!(
                                "Reputation stored at PC {} without time-based decay. Reputation permanent once earned. \
                                Issues: (1) Old/inactive accounts retain high reputation, (2) No incentive for continued \
                                good behavior, (3) Historical exploits remain influential. Implement decay: \
                                score *= (1 - decayRate * timeDelta).",
                                pc
                            ),
                            confidence: 0.65,
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
