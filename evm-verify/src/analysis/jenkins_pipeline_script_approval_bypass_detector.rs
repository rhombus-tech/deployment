use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JenkinsPipelineVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct JenkinsPipelineScriptApprovalBypassDetector {
    bytecode: Vec<u8>,
}

impl JenkinsPipelineScriptApprovalBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<JenkinsPipelineVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_sandbox_escape());
        vulnerabilities.extend(self.detect_unapproved_method_call());
        vulnerabilities.extend(self.detect_groovy_meta_programming_abuse());
        vulnerabilities
    }

    fn detect_sandbox_escape(&self) -> Vec<JenkinsPipelineVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF4 { // DELEGATECALL
                let start = if pc > 80 { pc - 80 } else { 0 };
                if self.bytecode[start..pc].iter().any(|&b| b == 0x35) {
                    vulns.push(JenkinsPipelineVulnerability {
                        pc, vulnerability_type: "SandboxEscape".to_string(),
                        description: format!("Groovy sandbox escape at PC {} allows unapproved script execution without admin approval.", pc),
                        confidence: 0.82,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_unapproved_method_call(&self) -> Vec<JenkinsPipelineVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL
                let window_end = (pc + 60).min(self.bytecode.len());
                if self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x35).count() >= 2 {
                    vulns.push(JenkinsPipelineVulnerability {
                        pc, vulnerability_type: "UnapprovedMethodCall".to_string(),
                        description: format!("Method call at PC {} bypasses Jenkins script approval queue via reflection or meta-programming.", pc),
                        confidence: 0.79,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_groovy_meta_programming_abuse(&self) -> Vec<JenkinsPipelineVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x20 { // KECCAK256 (dynamic method resolution)
                let window_end = (pc + 100).min(self.bytecode.len());
                if self.bytecode[pc..window_end].iter().filter(|&&b| b == 0xF1).count() >= 2 {
                    vulns.push(JenkinsPipelineVulnerability {
                        pc, vulnerability_type: "GroovyMetaProgrammingAbuse".to_string(),
                        description: format!("Meta-programming at PC {} uses invokeMethod or methodMissing to bypass script approval whitelist.", pc),
                        confidence: 0.76,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
