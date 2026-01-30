use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TimingAttackConstantTimeViolationDetector {
    bytecode: Vec<u8>,
}

impl TimingAttackConstantTimeViolationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<TimingVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect JUMPI after comparison operations (branching on secrets)
        vulnerabilities.extend(self.detect_comparison_branches());
        
        // Detect early returns via REVERT after EQ comparisons
        vulnerabilities.extend(self.detect_early_returns());

        vulnerabilities
    }

    fn detect_comparison_branches(&self) -> Vec<TimingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for comparison ops (EQ, LT, GT, etc.) followed by JUMPI
            if matches!(opcode, 0x10 | 0x11 | 0x12 | 0x13 | 0x14) { // EQ, GT, LT, etc.
                // Check next few instructions for JUMPI
                let window_end = (pc + 10).min(self.bytecode.len());
                for check_pc in (pc + 1)..window_end {
                    if self.bytecode[check_pc] == 0x57 { // JUMPI
                        vulns.push(TimingVulnerability {
                            pc,
                            vulnerability_type: "SecretDependentBranch".to_string(),
                            description: format!(
                                "Comparison at PC {} followed by conditional jump at PC {}. \
                                If this compares secret data (private keys, passwords, signatures), \
                                different code paths create timing side-channel. Use constant-time comparisons.",
                                pc, check_pc
                            ),
                            confidence: 0.70,
                        });
                        break;
                    }
                    // Stop at next comparison or jump
                    if self.bytecode[check_pc] >= 0x56 && self.bytecode[check_pc] <= 0x5B {
                        break;
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

    fn detect_early_returns(&self) -> Vec<TimingVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            
            // Look for EQ comparison followed by REVERT
            if opcode == 0x14 { // EQ
                let window_end = (pc + 15).min(self.bytecode.len());
                let mut found_jumpi = false;
                let mut found_revert = false;
                
                for check_pc in (pc + 1)..window_end {
                    let check_op = self.bytecode[check_pc];
                    if check_op == 0x57 { // JUMPI
                        found_jumpi = true;
                    }
                    if check_op == 0xFD { // REVERT
                        found_revert = true;
                        break;
                    }
                }
                
                if found_jumpi && found_revert {
                    vulns.push(TimingVulnerability {
                        pc,
                        vulnerability_type: "EarlyReturnLeak".to_string(),
                        description: format!(
                            "Equality check at PC {} leads to early REVERT. If comparing secrets \
                            (signature verification, password check), attacker can measure time difference \
                            between success/failure paths. Use constant-time validation.",
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
}
