use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LineaCanonicalMessageServiceVulnerability {
    MessageServiceRelay { description: String, location: usize, confidence: f32 },
    FeeManipulation { description: String, location: usize, confidence: f32 },
    MessageClaimingRace { description: String, location: usize, confidence: f32 },
}

pub struct LineaCanonicalMessageServiceDetector {
    bytecode: Vec<u8>,
}

impl LineaCanonicalMessageServiceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LineaCanonicalMessageServiceVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.relays_message() && !self.validates_merkle_proof() {
            vulnerabilities.push(LineaCanonicalMessageServiceVulnerability::MessageServiceRelay {
                description: "Message relay without merkle proof validation - forged message relay".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.calculates_fee() && !self.validates_fee_bounds() {
            vulnerabilities.push(LineaCanonicalMessageServiceVulnerability::FeeManipulation {
                description: "Fee calculation without bounds checking - excessive fee extraction".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.claims_message() && !self.prevents_double_claim() {
            vulnerabilities.push(LineaCanonicalMessageServiceVulnerability::MessageClaimingRace {
                description: "Message claiming without double-claim prevention - race condition".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn relays_message(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        call_count > 2 && sstore_count > 3
    }
    
    fn validates_merkle_proof(&self) -> bool {
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        sha3_count > 3 && eq_count > 3 && jumpi_count > 4
    }
    
    fn calculates_fee(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        mul_count > 2 && div_count > 1
    }
    
    fn validates_fee_bounds(&self) -> bool {
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        (lt_count + gt_count) > 2 && jumpi_count > 2
    }
    
    fn claims_message(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        sload_count > 4 && sstore_count > 3
    }
    
    fn prevents_double_claim(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        sload_count > 5 && iszero_count > 2 && sstore_count > 4
    }
}
