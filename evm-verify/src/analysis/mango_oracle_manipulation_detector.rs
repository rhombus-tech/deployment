use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MangoOracleVulnerability {
    TWAPManipulation { description: String, location: usize, confidence: f32 },
    MissingFundingRateSanity { description: String, location: usize, confidence: f32 },
    OracleStalenessNotChecked { description: String, location: usize, confidence: f32 },
    PerpFundingRateExploit { description: String, location: usize, confidence: f32 },
}

pub struct MangoOracleManipulationDetector {
    bytecode: Vec<u8>,
}

impl MangoOracleManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<MangoOracleVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_twap_manipulation());
        vulnerabilities.extend(self.detect_funding_rate_sanity());
        vulnerabilities.extend(self.detect_staleness_checks());
        vulnerabilities
    }
    
    fn detect_twap_manipulation(&self) -> Vec<MangoOracleVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if i + 80 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 80];
                let has_div = section.contains(&0x04);
                let has_timestamp = section.contains(&0x42);
                let has_bounds_check = section.windows(5).any(|w| (w.contains(&0x10) || w.contains(&0x12)) && w.contains(&0xFD));
                if has_div && has_timestamp && !has_bounds_check {
                    vulnerabilities.push(MangoOracleVulnerability::TWAPManipulation {
                        description: format!("TWAP oracle at PC {} vulnerable to spot price manipulation. Mango exploit: manipulated perp price → massive funding rate. Add min/max bounds on price changes.", i),
                        location: i,
                        confidence: 0.90,
                    });
                }
            }
        }
        vulnerabilities
    }
    
    fn detect_funding_rate_sanity(&self) -> Vec<MangoOracleVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if i + 100 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 100];
                let has_funding_calc = section.contains(&0x04) && section.contains(&0x02);
                let has_sanity_bounds = section.windows(8).any(|w| {
                    w.contains(&0x10) && w.contains(&0x12) && w.contains(&0xFD)
                });
                if has_funding_calc && !has_sanity_bounds {
                    vulnerabilities.push(MangoOracleVulnerability::MissingFundingRateSanity {
                        description: format!("Funding rate calculation at PC {} lacks bounds checking. Can result in extreme rates (Mango: funding rate spiked to liquidate positions). Add +/- 10% max per period.", i),
                        location: i,
                        confidence: 0.88,
                    });
                }
            }
        }
        vulnerabilities
    }
    
    fn detect_staleness_checks(&self) -> Vec<MangoOracleVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if i + 60 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 60];
                let has_oracle_call = section.contains(&0xFA);
                let has_timestamp_check = section.contains(&0x42) && section.contains(&0x03);
                if has_oracle_call && !has_timestamp_check {
                    vulnerabilities.push(MangoOracleVulnerability::OracleStalenessNotChecked {
                        description: format!("Oracle data at PC {} not checked for staleness. Should verify: block.timestamp - oracleTimestamp < MAX_DELAY (e.g., 300 seconds).", i),
                        location: i,
                        confidence: 0.85,
                    });
                }
            }
        }
        vulnerabilities
    }
}
