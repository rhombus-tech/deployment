use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeterministicDeploymentVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct DeterministicDeploymentProxyDetector {
    bytecode: Vec<u8>,
}

impl DeterministicDeploymentProxyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<DeterministicDeploymentVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_singleton_proxy_hijack());
        vulnerabilities.extend(self.detect_cross_chain_address_mismatch());
        vulnerabilities.extend(self.detect_immutable_deployment_lock());
        vulnerabilities
    }

    fn detect_singleton_proxy_hijack(&self) -> Vec<DeterministicDeploymentVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x3B { // EXTCODESIZE (singleton check)
                let window_end = (pc + 80).min(self.bytecode.len());
                if self.bytecode[pc..window_end].iter().any(|&b| b == 0xF5) {
                    let validates_deployer = self.bytecode[pc..window_end].iter().any(|&b| b == 0x33);
                    if !validates_deployer {
                        vulns.push(DeterministicDeploymentVulnerability {
                            pc, vulnerability_type: "SingletonProxyHijack".to_string(),
                            description: format!("Singleton deployment at PC {} doesn't validate deployer, attacker can frontrun and deploy malicious proxy.", pc),
                            confidence: 0.83,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_cross_chain_address_mismatch(&self) -> Vec<DeterministicDeploymentVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF5 { // CREATE2
                let start = if pc > 100 { pc - 100 } else { 0 };
                let uses_chainid = self.bytecode[start..pc].iter().any(|&b| b == 0x46);
                if !uses_chainid {
                    vulns.push(DeterministicDeploymentVulnerability {
                        pc, vulnerability_type: "CrossChainAddressMismatch".to_string(),
                        description: format!("CREATE2 at PC {} doesn't include chain ID in salt, different addresses on different chains break cross-chain assumptions.", pc),
                        confidence: 0.76,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_immutable_deployment_lock(&self) -> Vec<DeterministicDeploymentVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x3B { // EXTCODESIZE
                let window_end = (pc + 60).min(self.bytecode.len());
                if self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x57).count() >= 2 {
                    vulns.push(DeterministicDeploymentVulnerability {
                        pc, vulnerability_type: "ImmutableDeploymentLock".to_string(),
                        description: format!("Deployment check at PC {} prevents redeployment but no upgrade mechanism, contract stuck if bugs found.", pc),
                        confidence: 0.74,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
