/// ZK Rollup Proof Delay Detector
use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKRollupProofDelayVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

pub struct ZKRollupProofDelayDetector {
    bytecode: Vec<u8>,
}

impl ZKRollupProofDelayDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }

    pub fn detect_vulnerabilities(&self) -> Vec<ZKRollupProofDelayVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len().saturating_sub(200) {
            if self.detect_pattern(pc) && !self.has_protection(pc, 150) {
                vulnerabilities.push(ZKRollupProofDelayVulnerability {
                    severity: SecuritySeverity::High,
                    confidence: 0.80,
                    description: format!("ZK rollup proof generation delay exploitation at PC {}", pc),
                    exploit_scenario: "Exploit delay between tx submission and proof finalization\n\nFix: Add proof generation time limits".to_string(),
                    location: pc,
                });
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_pattern(&self, pc: usize) -> bool {
        pc + 100 < self.bytecode.len() && matches!(self.bytecode.get(pc), Some(&0x02) | Some(&0x04) | Some(&0x54) | Some(&0xf1))
    }

    fn has_protection(&self, pc: usize, range: usize) -> bool {
        (pc.saturating_sub(range/2)..pc+range/2).any(|i| matches!(self.bytecode.get(i), Some(&0x10) | Some(&0x11)) && (i+1..i+10).any(|j| self.bytecode.get(j) == Some(&0xfd)))
    }
}
