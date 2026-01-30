/// ERC-7303 Token-Controlled Progressive Decentralization Detector
/// Gradual transition from centralized to decentralized governance

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc7303Vulnerability {
    pub vulnerability_type: Erc7303VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc7303VulnerabilityType {
    DecentralizationThresholdManipulation,  // Token threshold gaming
    GovernanceTransitionRace,                // Race during transition period
    SupplyManipulationForControl,            // Inflate supply to delay decentralization
    EmergencyPowersPersist,                  // Admin powers not revoked
    VotingPowerConcentration,                // Few holders control transition
    SnapshotTimingExploit,                   // Manipulate snapshot for voting power
}

pub struct Erc7303ProgressiveDecentralizationDetector {
    bytecode: Vec<u8>,
}

impl Erc7303ProgressiveDecentralizationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Erc7303Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern: Threshold check without supply validation
        for i in 0..self.bytecode.len().saturating_sub(20) {
            let mut checks_threshold = false;
            let mut validates_supply = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x12 { // LT/SLT (threshold)
                    checks_threshold = true;
                }
                if self.bytecode[j] == 0x54 && j + 1 < self.bytecode.len() && self.bytecode[j+1] == 0x18 { // SLOAD + MUL
                    validates_supply = true;
                }
            }
            
            if checks_threshold && !validates_supply {
                vulnerabilities.push(Erc7303Vulnerability {
                    vulnerability_type: Erc7303VulnerabilityType::DecentralizationThresholdManipulation,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Decentralization threshold checked without total supply validation.".to_string(),
                    exploit_scenario: "1. Protocol: Decentralize when 10M tokens distributed\n\
                                      2. Current: 9M tokens circulating\n\
                                      3. Team mints 1M tokens to trigger threshold\n\
                                      4. Team controls 10% of supply pre-decentralization\n\
                                      5. Governance activates\n\
                                      6. Team immediately proposes malicious upgrade\n\
                                      7. Team's 10% + 5% allied holders = 15% control\n\
                                      8. Passes proposal with low participation\n\
                                      9. $50M protocol compromised via rushed decentralization".to_string(),
                    recommendation: "Validate total supply growth rate. Require time-weighted distribution. \
                                  Add minimum distribution duration. Check Gini coefficient for fair distribution.".to_string(),
                });
            }
        }
        
        // Pattern: Admin powers not revoked
        for i in 0..self.bytecode.len().saturating_sub(15) {
            let mut governance_active = false;
            let mut admin_check_present = false;
            
            for j in i..self.bytecode.len().min(i + 15) {
                if self.bytecode[j] == 0xF4 { // DELEGATECALL (governance)
                    governance_active = true;
                }
                if self.bytecode[j] == 0x33 { // CALLER
                    if j + 5 < self.bytecode.len() && self.bytecode[j+1] == 0x54 && self.bytecode[j+2] == 0x14 { // SLOAD EQ
                        admin_check_present = true;
                    }
                }
            }
            
            if governance_active && admin_check_present {
                vulnerabilities.push(Erc7303Vulnerability {
                    vulnerability_type: Erc7303VulnerabilityType::EmergencyPowersPersist,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Admin powers still active after governance transition.".to_string(),
                    exploit_scenario: "1. Protocol transitions to DAO governance\n\
                                      2. Community votes on proposals\n\
                                      3. Admin modifier still present in code\n\
                                      4. Original team retains emergency powers\n\
                                      5. Community votes to reduce team allocation\n\
                                      6. Team uses admin powers to veto\n\
                                      7. 'Decentralized' protocol still centralized\n\
                                      8. $100M TVL at risk from admin control".to_string(),
                    recommendation: "Renounce admin role on governance activation. Use timelock for all operations. \
                                  Implement guardian multisig only for critical emergencies.".to_string(),
                });
            }
        }
        
        vulnerabilities
    }
}
