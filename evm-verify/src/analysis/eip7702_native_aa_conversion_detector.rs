use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Eip7702NativeAaConversionVulnerability {
    EoaToSmartContractRisk { description: String, location: usize, confidence: f32 },
}

pub struct Eip7702NativeAaConversionDetector {
    bytecode: Vec<u8>,
}

impl Eip7702NativeAaConversionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Eip7702NativeAaConversionVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_eoa_conversion_logic() && !self.has_conversion_safeguards() {
            vulnerabilities.push(Eip7702NativeAaConversionVulnerability::EoaToSmartContractRisk {
                description: "EOA to smart contract conversion (EIP-7702) without proper safeguards".to_string(),
                location: 0,
                confidence: 0.75,
            });
        }
        
        vulnerabilities
    }
    
    fn has_eoa_conversion_logic(&self) -> bool {
        let extcodesize_count = self.bytecode.iter().filter(|&&b| b == 0x3B).count();
        extcodesize_count > 0
    }
    
    fn has_conversion_safeguards(&self) -> bool {
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        iszero_count > 2
    }
}
