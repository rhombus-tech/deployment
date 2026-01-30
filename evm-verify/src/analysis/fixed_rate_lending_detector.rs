/// Fixed-Rate Lending Detector (Notional, Exactly, Yield Protocol)
/// Fixed-term, fixed-rate lending protocols

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixedRateLendingVulnerability {
    pub vulnerability_type: FixedRateVulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FixedRateVulnerabilityType {
    MaturityManipulation,           // Manipulate maturity date
    InterestRateOracleAttack,       // Fixed rate oracle manipulation
    EarlyRedemptionExploit,         // Redeem before maturity unfairly
    RolloverRace,                   // Race during loan rollover
    YieldCurveManipulation,         // Manipulate implied yield curve
}

pub struct FixedRateLendingDetector {
    bytecode: Vec<u8>,
}

impl FixedRateLendingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<FixedRateLendingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: Maturity check without timestamp validation
        for i in 0..self.bytecode.len().saturating_sub(15) {
            let mut checks_maturity = false;
            let mut validates_timestamp = false;
            
            for j in i..self.bytecode.len().min(i + 15) {
                if self.bytecode[j] == 0x10 { checks_maturity = true; } // LT
                if self.bytecode[j] == 0x42 { validates_timestamp = true; } // TIMESTAMP
            }
            
            if checks_maturity && !validates_timestamp {
                vulnerabilities.push(FixedRateLendingVulnerability {
                    vulnerability_type: FixedRateVulnerabilityType::MaturityManipulation,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Maturity validation without proper timestamp check.".to_string(),
                    exploit_scenario: "1. User borrows 1000 USDC at 5% fixed for 1 year\n\
                                      2. Maturity: Jan 1, 2026\n\
                                      3. Current: June 1, 2025 (6 months in)\n\
                                      4. Attacker manipulates maturity storage\n\
                                      5. Changes maturity to June 1, 2025 (today)\n\
                                      6. Calls liquidate() - loan 'overdue'\n\
                                      7. Seizes $1500 collateral for $1025 debt\n\
                                      8. $475 profit from premature liquidation".to_string(),
                    recommendation: "Use immutable maturity timestamp. Validate against block.timestamp. \
                                  Add maturity hash verification.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}
