use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GithubActionsVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct GithubActionsSecretExposureInLogsDetector {
    bytecode: Vec<u8>,
}

impl GithubActionsSecretExposureInLogsDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<GithubActionsVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_secret_in_error_message());
        vulnerabilities.extend(self.detect_env_var_leak_in_logs());
        vulnerabilities.extend(self.detect_api_key_console_output());
        vulnerabilities
    }

    fn detect_secret_in_error_message(&self) -> Vec<GithubActionsVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xFD { // REVERT
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                if window.iter().filter(|&&b| b == 0x35).count() >= 2 && !window.iter().filter(|&&b| b == 0x20).count() >= 2 {
                    vulns.push(GithubActionsVulnerability {
                        pc, vulnerability_type: "SecretInErrorMessage".to_string(),
                        description: format!("Revert at PC {} may include sensitive data in error message logged by GitHub Actions.", pc),
                        confidence: 0.81,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_env_var_leak_in_logs(&self) -> Vec<GithubActionsVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x54 { // SLOAD
                let window_end = (pc + 80).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                if window.iter().any(|&b| b == 0x35) && !window.iter().any(|&b| b == 0x20) {
                    vulns.push(GithubActionsVulnerability {
                        pc, vulnerability_type: "EnvVarLeakInLogs".to_string(),
                        description: format!("Storage read at PC {} outputs environment variables that may contain secrets in CI logs.", pc),
                        confidence: 0.78,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_api_key_console_output(&self) -> Vec<GithubActionsVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x35 { // CALLDATALOAD
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                if window.iter().filter(|&&b| b == 0x35).count() >= 3 {
                    vulns.push(GithubActionsVulnerability {
                        pc, vulnerability_type: "ApiKeyConsoleOutput".to_string(),
                        description: format!("Data loading at PC {} may output API keys via console.log visible in GitHub Actions logs.", pc),
                        confidence: 0.75,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
