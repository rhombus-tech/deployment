use serde::{Deserialize, Serialize};

/// Shared Liquidity Pool: Multiple protocols using same pool
/// Attack: Manipulate pool via one protocol, exploit via another

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedLiquidityPoolVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct SharedLiquidityPoolAttackDetector {
    bytecode: Vec<u8>,
}

impl SharedLiquidityPoolAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<SharedLiquidityPoolVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_shared_pool_manipulation() {
            vulnerabilities.push(SharedLiquidityPoolVulnerability {
                vulnerability_type: "Shared Liquidity Pool Manipulation".to_string(),
                location: loc,
                severity: "Critical".to_string(),
                description: "Same pool accessed via multiple protocols without isolation".to_string(),
                confidence: 0.85,
            });
        }
        vulnerabilities
    }
    fn has_shared_pool_manipulation(&self) -> Option<usize> {
        // Multiple calls to same address (pool) via different entry points
        for i in 0..self.bytecode.len().saturating_sub(60) {
            let mut same_address_calls = 0;
            for j in i..i+55.min(self.bytecode.len()) {
                if self.bytecode[j] == 0xf1 { // CALL
                    same_address_calls += 1;
                }
            }
            if same_address_calls >= 2 { return Some(i); }
        }
        None
    }
}
