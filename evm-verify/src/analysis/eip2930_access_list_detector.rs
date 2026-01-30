/// EIP-2930 Access List Transaction Detector
/// Type 1 transaction vulnerabilities

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip2930Vulnerability {
    pub vulnerability_type: Eip2930VulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Eip2930VulnerabilityType {
    AccessListManipulation,         // Access list manipulated for gas advantage
    StorageSlotExposure,            // Access list reveals storage slots
    GasExploitation,                // Gas cost manipulation
    FrontrunningViaAccessList,      // Access list used for frontrunning
}

pub struct Eip2930AccessListDetector {
    bytecode: Vec<u8>,
}

impl Eip2930AccessListDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<Eip2930Vulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x54 { // SLOAD
                vulnerabilities.push(Eip2930Vulnerability {
                    vulnerability_type: Eip2930VulnerabilityType::StorageSlotExposure,
                    severity: "Low".to_string(),
                    location: vec![i],
                    description: "Storage access patterns can be revealed via EIP-2930 access lists.".to_string(),
                    exploit_scenario: "1. Contract has private storage slots\n\
                                      2. Attacker observes access list\n\
                                      3. Identifies which slots are accessed\n\
                                      4. Gains information about contract state\n\
                                      5. Uses info for targeted attacks".to_string(),
                    recommendation: "Be aware access lists reveal storage access patterns. \
                                  Don't rely on storage slot privacy.".to_string(),
                });
                break; // Only report once
            }
        }
        
        vulnerabilities
    }
}
