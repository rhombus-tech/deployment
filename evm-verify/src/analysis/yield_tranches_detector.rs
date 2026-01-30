/// Yield Tranches Detector (Idle Finance, Saffron Finance)
/// Senior/junior tranche yield strategies

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YieldTranchesVulnerability {
    pub vulnerability_type: TrancheVulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrancheVulnerabilityType {
    WaterfallBypass,                // Bypass payment waterfall
    SeniorTrancheUnderpayment,      // Senior tranche not paid first
    JuniorTrancheOverpayment,       // Junior paid before senior
    LossAllocationManipulation,     // Manipulate loss distribution
    TrancheRatioManipulation,       // Change senior/junior ratio
}

pub struct YieldTranchesDetector {
    bytecode: Vec<u8>,
}

impl YieldTranchesDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<YieldTranchesVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: Distribution without waterfall ordering
        for i in 0..self.bytecode.len().saturating_sub(25) {
            let mut distributes_yield = false;
            let mut checks_senior_first = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                if self.bytecode[j] == 0xF1 { distributes_yield = true; }
                if self.bytecode[j] == 0x54 && j + 3 < self.bytecode.len() {
                    if self.bytecode[j+1] == 0x14 { // SLOAD EQ (senior check)
                        checks_senior_first = true;
                    }
                }
            }
            
            if distributes_yield && !checks_senior_first {
                vulnerabilities.push(YieldTranchesVulnerability {
                    vulnerability_type: TrancheVulnerabilityType::WaterfallBypass,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Yield distributed without waterfall validation.".to_string(),
                    exploit_scenario: "1. Vault has $1M senior tranche, $200K junior tranche\n\
                                      2. Senior expects 5% ($50K), junior expects upside\n\
                                      3. Vault earns $80K total\n\
                                      4. distributeYield() doesn't check waterfall\n\
                                      5. Distributes pro-rata: Senior gets $66K, Junior gets $14K\n\
                                      6. Senior entitled to $50K + remaining $30K = $80K\n\
                                      7. Junior should get $0 (didn't cover senior)\n\
                                      8. Senior loses $14K to junior incorrectly".to_string(),
                    recommendation: "Implement strict waterfall: 1) Pay senior fixed yield 2) Cover losses 3) Excess to junior. \
                                  Add tranche priority validation.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}
