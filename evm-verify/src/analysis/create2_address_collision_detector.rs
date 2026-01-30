use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Create2Vulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct Create2AddressCollisionDetector {
    bytecode: Vec<u8>,
}

impl Create2AddressCollisionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<Create2Vulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_weak_salt_entropy());
        vulnerabilities.extend(self.detect_predictable_deployment_address());
        vulnerabilities.extend(self.detect_selfdestruct_redeploy_attack());
        vulnerabilities
    }

    fn detect_weak_salt_entropy(&self) -> Vec<Create2Vulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF5 { // CREATE2
                let start = if pc > 100 { pc - 100 } else { 0 };
                let has_strong_entropy = self.bytecode[start..pc].iter().filter(|&&b| matches!(b, 0x20 | 0x42 | 0x44)).count() >= 2;
                if !has_strong_entropy {
                    vulns.push(Create2Vulnerability {
                        pc, vulnerability_type: "WeakSaltEntropy".to_string(),
                        description: format!("CREATE2 salt at PC {} uses weak entropy, attacker can grind salt to create address collision.", pc),
                        confidence: 0.79,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_predictable_deployment_address(&self) -> Vec<Create2Vulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF5 { // CREATE2
                let start = if pc > 80 { pc - 80 } else { 0 };
                if self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 2 {
                    vulns.push(Create2Vulnerability {
                        pc, vulnerability_type: "PredictableDeploymentAddress".to_string(),
                        description: format!("CREATE2 address at PC {} predictable from user input, allows frontrunning deployment with malicious contract.", pc),
                        confidence: 0.82,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_selfdestruct_redeploy_attack(&self) -> Vec<Create2Vulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xFF { // SELFDESTRUCT
                let window_end = (pc + 150).min(self.bytecode.len());
                if window_end < self.bytecode.len() && self.bytecode[pc..window_end].iter().any(|&b| b == 0xF5) {
                    vulns.push(Create2Vulnerability {
                        pc, vulnerability_type: "SelfdestructRedeployAttack".to_string(),
                        description: format!("SELFDESTRUCT at PC {} followed by CREATE2 allows metamorphic contracts with different code at same address.", pc),
                        confidence: 0.88,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
