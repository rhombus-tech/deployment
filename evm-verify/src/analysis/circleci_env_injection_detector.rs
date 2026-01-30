use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircleCiVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CircleCiEnvInjectionDetector {
    bytecode: Vec<u8>,
}

impl CircleCiEnvInjectionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CircleCiVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_context_injection());
        vulnerabilities.extend(self.detect_unvalidated_pr_number());
        vulnerabilities.extend(self.detect_branch_name_command_injection());
        vulnerabilities
    }

    fn detect_context_injection(&self) -> Vec<CircleCiVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x35 { // CALLDATALOAD
                let window_end = (pc + 100).min(self.bytecode.len());
                if window_end - pc > 50 && !self.bytecode[pc..window_end].iter().any(|&b| b == 0x20) {
                    vulns.push(CircleCiVulnerability {
                        pc, vulnerability_type: "ContextInjection".to_string(),
                        description: format!("Environment variable usage at PC {} doesn't sanitize CircleCI context values, allowing command injection.", pc),
                        confidence: 0.80,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_unvalidated_pr_number(&self) -> Vec<CircleCiVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x54 { // SLOAD
                let window_end = (pc + 80).min(self.bytecode.len());
                if self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x35).count() >= 2 {
                    vulns.push(CircleCiVulnerability {
                        pc, vulnerability_type: "UnvalidatedPrNumber".to_string(),
                        description: format!("PR number at PC {} used without validation, attacker can inject malicious PR numbers in forked workflows.", pc),
                        confidence: 0.77,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_branch_name_command_injection(&self) -> Vec<CircleCiVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL
                let start = if pc > 100 { pc - 100 } else { 0 };
                if self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 2 {
                    vulns.push(CircleCiVulnerability {
                        pc, vulnerability_type: "BranchNameCommandInjection".to_string(),
                        description: format!("Branch name used in command at PC {} without escaping, malicious branch names can execute arbitrary commands.", pc),
                        confidence: 0.83,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
