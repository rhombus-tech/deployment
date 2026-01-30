use serde::{Deserialize, Serialize};

/// Volatility Swap Arbitrage Detector
/// Vol Swap pays: Realized Vol - Strike Vol
/// Arbitrage: Realized vol calculated from on-chain prices can be gamed

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolatilitySwapVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct VolatilitySwapArbitrageDetector {
    bytecode: Vec<u8>,
}

impl VolatilitySwapArbitrageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<VolatilitySwapVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_realized_vol_gaming() {
            vulnerabilities.push(VolatilitySwapVulnerability {
                vulnerability_type: "Realized Volatility Gaming".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Realized vol calculation gameable via price manipulation".to_string(),
                confidence: 0.85,
            });
        }
        if let Some(loc) = self.has_variance_calculation_overflow() {
            vulnerabilities.push(VolatilitySwapVulnerability {
                vulnerability_type: "Variance Calculation Overflow".to_string(),
                location: loc,
                severity: "Medium".to_string(),
                description: "Variance sum can overflow with extreme price moves".to_string(),
                confidence: 0.75,
            });
        }
        vulnerabilities
    }
    fn has_realized_vol_gaming(&self) -> Option<usize> {
        // Realized vol = sqrt(sum of squared returns)
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x5b { // Loop (summing returns)
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x02 { // MUL (squaring)
                        return Some(i);
                    }
                }
            }
        }
        None
    }
    fn has_variance_calculation_overflow(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x02 && // MUL (r^2)
               self.bytecode.get(i+3) == Some(&0x01) { // ADD (sum)
                return Some(i);
            }
        }
        None
    }
}
