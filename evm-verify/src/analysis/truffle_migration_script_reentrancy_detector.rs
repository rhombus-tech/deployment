use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TruffleMigrationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TruffleMigrationScriptReentrancyDetector {
    bytecode: Vec<u8>,
}

impl TruffleMigrationScriptReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<TruffleMigrationVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_deployment_reentrancy());
        vulnerabilities.extend(self.detect_initialization_race_condition());
        vulnerabilities.extend(self.detect_deployment_order_dependency());
        vulnerabilities
    }

    fn detect_deployment_reentrancy(&self) -> Vec<TruffleMigrationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF0 { // CREATE
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                if window.iter().any(|&b| b == 0xF1) && !window.iter().any(|&b| b == 0x55) {
                    vulns.push(TruffleMigrationVulnerability {
                        pc, vulnerability_type: "DeploymentReentrancy".to_string(),
                        description: format!("Contract deployment at PC {} followed by call allows reentrancy before state initialized.", pc),
                        confidence: 0.85,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_initialization_race_condition(&self) -> Vec<TruffleMigrationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (initialization)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                if window.iter().filter(|&&b| b == 0xF1).count() >= 2 {
                    vulns.push(TruffleMigrationVulnerability {
                        pc, vulnerability_type: "InitializationRaceCondition".to_string(),
                        description: format!("Initialization at PC {} after external calls allows front-running of init function.", pc),
                        confidence: 0.81,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_deployment_order_dependency(&self) -> Vec<TruffleMigrationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF0 || opcode == 0xF5 { // CREATE/CREATE2
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                if window.iter().filter(|&&b| b == 0x35).count() >= 2 && !window.iter().any(|&b| b == 0x54) {
                    vulns.push(TruffleMigrationVulnerability {
                        pc, vulnerability_type: "DeploymentOrderDependency".to_string(),
                        description: format!("Deployment at PC {} depends on deployment order but Truffle may execute migrations out of order.", pc),
                        confidence: 0.77,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
