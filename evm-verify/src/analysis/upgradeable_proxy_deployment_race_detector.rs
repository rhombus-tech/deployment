use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentRaceVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct UpgradeableProxyDeploymentRaceDetector {
    bytecode: Vec<u8>,
}

impl UpgradeableProxyDeploymentRaceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<DeploymentRaceVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_uninitialized_implementation_window());
        vulnerabilities.extend(self.detect_proxy_implementation_gap());
        vulnerabilities.extend(self.detect_initialization_frontrun());
        vulnerabilities
    }

    fn detect_uninitialized_implementation_window(&self) -> Vec<DeploymentRaceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF0 { // CREATE
                let window_end = (pc + 120).min(self.bytecode.len());
                let has_init = self.bytecode[pc..window_end].iter().any(|&b| b == 0xF1);
                if has_init && self.bytecode[pc..window_end].iter().filter(|&&b| b == 0xF0).count() >= 2 {
                    vulns.push(DeploymentRaceVulnerability {
                        pc, vulnerability_type: "UninitializedImplementationWindow".to_string(),
                        description: format!("Proxy deployment at PC {} creates implementation before initialization, allowing attacker to initialize first.", pc),
                        confidence: 0.84,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_proxy_implementation_gap(&self) -> Vec<DeploymentRaceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (implementation address)
                let start = if pc > 100 { pc - 100 } else { 0 };
                if self.bytecode[start..pc].iter().filter(|&&b| b == 0xF0).count() >= 1 {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    if !self.bytecode[pc..window_end].iter().any(|&b| b == 0xF1) {
                        vulns.push(DeploymentRaceVulnerability {
                            pc, vulnerability_type: "ProxyImplementationGap".to_string(),
                            description: format!("Proxy set at PC {} without immediate initialization, time window allows unauthorized calls.", pc),
                            confidence: 0.81,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_initialization_frontrun(&self) -> Vec<DeploymentRaceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL (initialize)
                let start = if pc > 120 { pc - 120 } else { 0 };
                if self.bytecode[start..pc].iter().any(|&b| b == 0xF0) {
                    let has_access_control = self.bytecode[start..pc].iter().filter(|&&b| b == 0x33).count() >= 2;
                    if !has_access_control {
                        vulns.push(DeploymentRaceVulnerability {
                            pc, vulnerability_type: "InitializationFrontrun".to_string(),
                            description: format!("Initialization at PC {} lacks access control, attacker can frontrun deployment transaction and become owner.", pc),
                            confidence: 0.87,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
