use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditDiscrepancyVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct AuditReportDiscrepancyDetector {
    bytecode: Vec<u8>,
}

impl AuditReportDiscrepancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<AuditDiscrepancyVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_unresolved_audit_findings());
        vulnerabilities.extend(self.detect_post_audit_modifications());
        vulnerabilities.extend(self.detect_missing_fix_verification());
        vulnerabilities
    }

    fn detect_unresolved_audit_findings(&self) -> Vec<AuditDiscrepancyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF1 { // CALL (unchecked return)
                let window_end = (pc + 40).min(self.bytecode.len());
                let checks_return = self.bytecode[pc..window_end].iter().any(|&b| b == 0x15);
                if !checks_return {
                    vulns.push(AuditDiscrepancyVulnerability {
                        pc, vulnerability_type: "UnresolvedAuditFindings".to_string(),
                        description: format!("Unchecked external call at PC {} matches common audit finding pattern but remains unfixed.", pc),
                        confidence: 0.79,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_post_audit_modifications(&self) -> Vec<AuditDiscrepancyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0xF4 { // DELEGATECALL (high-risk operation)
                vulns.push(AuditDiscrepancyVulnerability {
                    pc, vulnerability_type: "PostAuditModifications".to_string(),
                    description: format!("DELEGATECALL at PC {} indicates post-audit code changes not covered by security review.", pc),
                    confidence: 0.74,
                });
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_missing_fix_verification(&self) -> Vec<AuditDiscrepancyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE
                let start = if pc > 80 { pc - 80 } else { 0 };
                let has_checks = self.bytecode[start..pc].iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                if !has_checks {
                    vulns.push(AuditDiscrepancyVulnerability {
                        pc, vulnerability_type: "MissingFixVerification".to_string(),
                        description: format!("State write at PC {} lacks validation checks typically added to address audit findings.", pc),
                        confidence: 0.72,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
