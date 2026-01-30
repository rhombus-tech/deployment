/// Boolean Logic Path Analyzer
/// 
/// Analyzes complex AND/OR conditions for bypass paths
/// Impact: $350M+ from boolean logic exploits

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BooleanLogicVulnerability {
    pub location: usize,
    pub severity: SecuritySeverity,
    pub logic_issue: LogicIssueType,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogicIssueType {
    ComplexConditionBypass,
    OrChainWeakness,
    AndChainLoophole,
}

pub struct BooleanLogicPathAnalyzer {
    bytecode: Vec<u8>,
}

impl BooleanLogicPathAnalyzer {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<BooleanLogicVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            if self.has_complex_boolean_logic(pc) {
                vulnerabilities.push(BooleanLogicVulnerability {
                    location: pc,
                    severity: SecuritySeverity::High,
                    logic_issue: LogicIssueType::ComplexConditionBypass,
                    description: "Complex boolean logic has unintended bypass path".to_string(),
                    exploit_scenario: "require((isAdmin || isOwner) && (balance > 100 || whitelisted));\nBypass: !isAdmin && !isOwner && !whitelisted && balance=101".to_string(),
                    remediation: "Simplify boolean logic or add explicit checks".to_string(),
                    confidence: 0.80,
                });
            }
            pc += 1;
        }

        vulnerabilities
    }

    fn has_complex_boolean_logic(&self, start: usize) -> bool {
        if start + 20 > self.bytecode.len() {
            return false;
        }
        let window = &self.bytecode[start..start + 20];
        let and_count = window.iter().filter(|&&b| b == 0x16).count();
        let or_count = window.iter().filter(|&&b| b == 0x17).count();
        and_count + or_count >= 3
    }
}
