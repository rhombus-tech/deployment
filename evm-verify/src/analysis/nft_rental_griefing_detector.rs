use serde::{Serialize, Deserialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NftRentalGriefingDetectorVulnerability {
    RenterGriefing { description: String, location: usize },
}
pub struct NftRentalGriefingDetector { bytecode: Vec<u8> }
impl NftRentalGriefingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self { Self { bytecode } }
    pub fn detect_vulnerabilities(&self) -> Vec<NftRentalGriefingDetectorVulnerability> {
        let mut vulnerabilities = Vec::new();
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x42 { // TIMESTAMP (rental period)
                let has_deposit = self.bytecode[i..std::cmp::min(i+40, self.bytecode.len())]
                    .iter().any(|&b| b == 0x54); // SLOAD (deposit check)
                if !has_deposit {
                    vulnerabilities.push(NftRentalGriefingDetectorVulnerability::RenterGriefing {
                        description: "Rental without deposit protection".to_string(), location: i,
                    });
                    break;
                }
            }
        }
        vulnerabilities
    }
}