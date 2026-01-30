/// Virtual Reserves Manipulation Detector
/// Detects virtual reserves k-value manipulation

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualReservesManipulationVulnerability {
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

pub struct VirtualReservesManipulationDetector {
    bytecode: Vec<u8>,
}

impl VirtualReservesManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<VirtualReservesManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_primary_vulnerability());
        vulnerabilities.extend(self.detect_secondary_vulnerability());
        vulnerabilities.extend(self.detect_edge_case_vulnerability());
        vulnerabilities
    }

    fn detect_primary_vulnerability(&self) -> Vec<VirtualReservesManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(250) {
            if self.is_vulnerable_operation(pc) && !self.has_primary_protection(pc, 200) {
                vulnerabilities.push(VirtualReservesManipulationVulnerability {
                    severity: SecuritySeverity::Critical,
                    confidence: 0.85,
                    description: format!("virtual reserves k-value manipulation at PC {}", pc),
                    exploit_scenario: "Manipulate virtual reserves to break constant product
Attacker exploits k=x*y invariant weakness
Virtual offsets allow price manipulation
Pool becomes insolvent".to_string(),
                    location: pc,
                });
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_secondary_vulnerability(&self) -> Vec<VirtualReservesManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(220) {
            if self.is_vulnerable_operation(pc) && self.has_secondary_risk(pc, 180) {
                vulnerabilities.push(VirtualReservesManipulationVulnerability {
                    severity: SecuritySeverity::High,
                    confidence: 0.75,
                    description: format!("Secondary virtual reserves k-value manipulation risk at PC {}", pc),
                    exploit_scenario: "Secondary: Amplified pool exploitation
Use amplification factor against pool
Create asymmetric slippage
Drain one side of pool".to_string(),
                    location: pc,
                });
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn detect_edge_case_vulnerability(&self) -> Vec<VirtualReservesManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len().saturating_sub(200) {
            if self.is_vulnerable_operation(pc) && !self.has_edge_case_handling(pc, 150) {
                vulnerabilities.push(VirtualReservesManipulationVulnerability {
                    severity: SecuritySeverity::Medium,
                    confidence: 0.70,
                    description: format!("Edge case virtual reserves k-value manipulation at PC {}", pc),
                    exploit_scenario: "Edge case: Rounding in virtual reserves
Exploit rounding errors in calculations
Accumulate dust over time".to_string(),
                    location: pc,
                });
            }
            pc += 1;
        }
        vulnerabilities
    }

    fn is_vulnerable_operation(&self, pc: usize) -> bool {
        if pc + 100 >= self.bytecode.len() { return false; }
        matches!(self.bytecode.get(pc), Some(&0x02) | Some(&0x04) | Some(&0x54) | Some(&0x55) | Some(&0xf1) | Some(&0xfa))
    }

    fn has_primary_protection(&self, pc: usize, range: usize) -> bool {
        for i in pc.saturating_sub(range/2)..(pc+range/2).min(self.bytecode.len()) {
            if matches!(self.bytecode.get(i), Some(&0x10) | Some(&0x11)) {
                if (i+1..i+10).any(|j| self.bytecode.get(j) == Some(&0xfd)) { return true; }
            }
        }
        false
    }

    fn has_secondary_risk(&self, pc: usize, range: usize) -> bool {
        (pc..pc+range).filter(|&i| matches!(self.bytecode.get(i), Some(&0xf1) | Some(&0xf2))).count() >= 2
    }

    fn has_edge_case_handling(&self, pc: usize, range: usize) -> bool {
        (pc.saturating_sub(range/2)..pc+range/2).any(|i| matches!(self.bytecode.get(i), Some(&0x14) | Some(&0x15)))
    }
}
