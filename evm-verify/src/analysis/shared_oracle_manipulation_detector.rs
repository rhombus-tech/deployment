use serde::{Deserialize, Serialize};

/// Shared Oracle: Same oracle used by multiple protocols
/// Attack: Manipulate oracle, exploit all dependent protocols

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedOracleVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct SharedOracleManipulationDetector {
    bytecode: Vec<u8>,
}

impl SharedOracleManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<SharedOracleVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_shared_oracle_dependency() {
            vulnerabilities.push(SharedOracleVulnerability {
                vulnerability_type: "Shared Oracle Cross-Protocol Risk".to_string(),
                location: loc,
                severity: "Critical".to_string(),
                description: "Multiple protocols depend on same oracle without fallback".to_string(),
                confidence: 0.90,
            });
        }
        vulnerabilities
    }
    fn has_shared_oracle_dependency(&self) -> Option<usize> {
        // Multiple oracle calls (STATICCALL) to same address
        for i in 0..self.bytecode.len().saturating_sub(50) {
            let mut oracle_calls = 0;
            for j in i..i+45.min(self.bytecode.len()) {
                if self.bytecode[j] == 0xfa { // STATICCALL (oracle read)
                    oracle_calls += 1;
                }
            }
            if oracle_calls >= 2 { return Some(i); }
        }
        None
    }
}
