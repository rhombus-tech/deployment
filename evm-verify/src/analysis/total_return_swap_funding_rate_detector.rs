use serde::{Deserialize, Serialize};

/// Total Return Swap: Exchange total returns for funding rate
/// Funding rate manipulation affects payout

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotalReturnSwapVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TotalReturnSwapFundingRateDetector {
    bytecode: Vec<u8>,
}

impl TotalReturnSwapFundingRateDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<TotalReturnSwapVulnerability> {
        let mut vulnerabilities = Vec::new();
        if let Some(loc) = self.has_funding_rate_manipulation() {
            vulnerabilities.push(TotalReturnSwapVulnerability {
                vulnerability_type: "Funding Rate Manipulation".to_string(),
                location: loc,
                severity: "High".to_string(),
                description: "Funding rate calculated from manipulatable rate source".to_string(),
                confidence: 0.80,
            });
        }
        vulnerabilities
    }
    fn has_funding_rate_manipulation(&self) -> Option<usize> {
        // Funding rate: interest rate oracle without TWAP
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xfa { // Oracle call
                let mut has_time_weighting = false;
                for j in i+1..i+25.min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x42 { // TIMESTAMP (for TWAP)
                        has_time_weighting = true;
                    }
                }
                if !has_time_weighting { return Some(i); }
            }
        }
        None
    }
}
