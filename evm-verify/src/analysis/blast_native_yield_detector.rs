/// Blast L2 Native Yield Detector
/// Auto-rebasing ETH and USDB on Blast L2

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastNativeYieldVulnerability {
    pub vulnerability_type: BlastYieldVulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlastYieldVulnerabilityType {
    YieldClaimFrontrunning,         // Frontrun yield claim
    RebasingBalanceManipulation,    // Exploit auto-rebasing
    YieldModeBypass,                // Change yield mode unauthorized
    ClaimableYieldRace,             // Race condition on yield claim
    VoidYieldModeExploit,            // Void mode yield accumulation
}

pub struct BlastNativeYieldDetector {
    bytecode: Vec<u8>,
}

impl BlastNativeYieldDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<BlastNativeYieldVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: Yield claim without access control
        for i in 0..self.bytecode.len().saturating_sub(15) {
            let mut claims_yield = false;
            let mut checks_auth = false;
            
            for j in i..self.bytecode.len().min(i + 15) {
                if self.bytecode[j] == 0xF1 { claims_yield = true; } // CALL (claimYield)
                if self.bytecode[j] == 0x33 && j + 2 < self.bytecode.len() && self.bytecode[j+1] == 0x14 {
                    checks_auth = true;
                }
            }
            
            if claims_yield && !checks_auth {
                vulnerabilities.push(BlastNativeYieldVulnerability {
                    vulnerability_type: BlastYieldVulnerabilityType::YieldClaimFrontrunning,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Blast yield claim without authorization.".to_string(),
                    exploit_scenario: "1. Contract holds 100 ETH on Blast\n\
                                      2. Accumulated 5 ETH yield (5% APY)\n\
                                      3. Owner calls claimYield()\n\
                                      4. No access control on claim function\n\
                                      5. Attacker frontruns with higher gas\n\
                                      6. Attacker's claimYield() executes first\n\
                                      7. Yield redirected to attacker\n\
                                      8. Owner loses 5 ETH ($10K) yield".to_string(),
                    recommendation: "Add onlyOwner modifier. Use claimAllYield with proper auth. \
                                  Implement yield recipient validation.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}
