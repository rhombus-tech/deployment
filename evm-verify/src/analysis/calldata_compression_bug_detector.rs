use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CalldataCompressionBugVulnerability {
    DecompressionOverflow { description: String, location: usize, confidence: f32 },
}

pub struct CalldataCompressionBugDetector {
    bytecode: Vec<u8>,
}

impl CalldataCompressionBugDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CalldataCompressionBugVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_calldata_decompression() && !self.validates_decompression_bounds() {
            vulnerabilities.push(CalldataCompressionBugVulnerability::DecompressionOverflow {
                description: "Calldata decompression without bounds checking - overflow risk".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        vulnerabilities
    }
    
    fn has_calldata_decompression(&self) -> bool {
        let calldataload_count = self.bytecode.iter().filter(|&&b| b == 0x35).count();
        let shl_count = self.bytecode.iter().filter(|&&b| b == 0x1B).count();
        calldataload_count > 3 && shl_count > 2
    }
    
    fn validates_decompression_bounds(&self) -> bool {
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        lt_count > 3
    }
}
