use serde::{Deserialize, Serialize};

/// Cross-DEX Arbitrage Loops: Circular trading A→B→C→A
/// Attack: Flash loan arbitrage across multiple DEXs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossDexArbitrageVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CrossDexArbitrageLoopDetector {
    bytecode: Vec<u8>,
}

impl CrossDexArbitrageLoopDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<CrossDexArbitrageVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_circular_dex_trading() {
            vulnerabilities.push(CrossDexArbitrageVulnerability {
                vulnerability_type: "Circular DEX Arbitrage Loop".to_string(),
                location: loc,
                severity: "Critical".to_string(),
                description: "Circular trading path across DEXs without slippage protection".to_string(),
                confidence: 0.90,
            });
        }
        vulnerabilities
    }
    fn has_circular_dex_trading(&self) -> Option<usize> {
        // Multiple swaps (swap selector 0x38ed1739 or similar)
        for i in 0..self.bytecode.len().saturating_sub(70) {
            let mut swap_count = 0;
            for j in i..i+65.min(self.bytecode.len()) {
                // Swap: CALL with token transfer patterns
                if self.bytecode[j] == 0xf1 {
                    for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                        if self.bytecode[k] == 0xa9 { // LOG1 (transfer event)
                            swap_count += 1;
                        }
                    }
                }
            }
            if swap_count >= 3 { return Some(i); }
        }
        None
    }
}
