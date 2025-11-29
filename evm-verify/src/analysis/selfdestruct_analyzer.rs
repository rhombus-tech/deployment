/// Enhanced SELFDESTRUCT Analyzer
use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfdestructVulnerability {
    pub vulnerability_type: SelfdestructIssue,
    pub severity: SecuritySeverity,
    pub description: String,
    pub attack_scenario: String,
    pub remediation: String,
    pub pc: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SelfdestructIssue {
    UnprotectedSelfdestruct,
    ForceSendEther,
    MetamorphicContract,
    ArbitraryBeneficiary,
}

pub struct SelfdestructAnalyzer {
    bytecode: Vec<u8>,
}

impl SelfdestructAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn analyze(&self) -> Vec<SelfdestructVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_unprotected_selfdestruct());
        vulnerabilities.extend(self.detect_metamorphic_risk());
        vulnerabilities
    }

    fn detect_unprotected_selfdestruct(&self) -> Vec<SelfdestructVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            if self.bytecode[pc] == 0xFF {  // SELFDESTRUCT
                if !self.has_caller_check_before(pc, 100) {
                    vulns.push(SelfdestructVulnerability {
                        vulnerability_type: SelfdestructIssue::UnprotectedSelfdestruct,
                        severity: SecuritySeverity::Critical,
                        description: "SELFDESTRUCT without access control".to_string(),
                        attack_scenario: "Anyone can destroy contract and steal funds".to_string(),
                        remediation: "Add onlyOwner modifier".to_string(),
                        pc,
                    });
                }
            }
            pc += 1;
            if self.bytecode[pc-1] >= 0x60 && self.bytecode[pc-1] <= 0x7F {
                pc += (self.bytecode[pc-1] - 0x5F) as usize;
            }
        }
        vulns
    }

    fn detect_metamorphic_risk(&self) -> Vec<SelfdestructVulnerability> {
        let mut vulns = Vec::new();
        let has_selfdestruct = self.bytecode.iter().any(|&b| b == 0xFF);
        let has_create2 = self.bytecode.iter().any(|&b| b == 0xF5);

        if has_selfdestruct && has_create2 {
            vulns.push(SelfdestructVulnerability {
                vulnerability_type: SelfdestructIssue::MetamorphicContract,
                severity: SecuritySeverity::Critical,
                description: "Metamorphic contract pattern detected".to_string(),
                attack_scenario: "Can redeploy malicious code at same address".to_string(),
                remediation: "Remove SELFDESTRUCT or CREATE2".to_string(),
                pc: 0,
            });
        }
        vulns
    }

    fn has_caller_check_before(&self, pc: usize, window: usize) -> bool {
        let start = pc.saturating_sub(window);
        self.bytecode[start..pc].iter().any(|&b| b == 0x33)
    }
}
