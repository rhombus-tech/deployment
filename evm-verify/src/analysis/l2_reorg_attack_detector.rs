use serde::{Deserialize, Serialize};

/// L2 Reorg Attack: L2 chain reorganization after finality assumption
/// Attack: Exploit soft finality vs hard finality gap

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2ReorgVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct L2ReorgAttackDetector {
    bytecode: Vec<u8>,
}

impl L2ReorgAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<L2ReorgVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_soft_finality_assumption() {
            vulnerabilities.push(L2ReorgVulnerability {
                vulnerability_type: "Soft Finality Assumption".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Assumes L2 finality without L1 settlement check".to_string(),
                confidence: 0.85,
            });
        }
        vulnerabilities
    }
    fn has_soft_finality_assumption(&self) -> Option<usize> {
        // State update without L1 confirmation
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 { // SSTORE
                let mut has_l1_check = false;
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0xfa { // STATICCALL (L1 verification)
                        has_l1_check = true;
                    }
                }
                if !has_l1_check { return Some(i); }
            }
        }
        None
    }
}
