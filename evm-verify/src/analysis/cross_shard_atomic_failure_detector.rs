use serde::{Deserialize, Serialize};

/// Cross-Shard Atomic Failure: Multi-shard transaction partial failure
/// Attack: One shard succeeds, another fails, breaking atomicity

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossShardAtomicVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CrossShardAtomicFailureDetector {
    bytecode: Vec<u8>,
}

impl CrossShardAtomicFailureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<CrossShardAtomicVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_broken_atomicity() {
            vulnerabilities.push(CrossShardAtomicVulnerability {
                vulnerability_type: "Cross-Shard Atomicity Failure".to_string(),
                location: loc,
                severity: "Critical".to_string(),
                description: "Multi-shard operation without rollback mechanism".to_string(),
                confidence: 0.85,
            });
        }
        vulnerabilities
    }
    fn has_broken_atomicity(&self) -> Option<usize> {
        // Multiple external calls without revert on failure
        for i in 0..self.bytecode.len().saturating_sub(35) {
            let mut call_count = 0;
            let mut has_revert_logic = false;
            for j in i..i+30.min(self.bytecode.len()) {
                if self.bytecode[j] == 0xf1 || self.bytecode[j] == 0xf4 { // CALL/DELEGATECALL
                    call_count += 1;
                }
                if self.bytecode[j] == 0xfd { // REVERT
                    has_revert_logic = true;
                }
            }
            if call_count >= 2 && !has_revert_logic { return Some(i); }
        }
        None
    }
}
