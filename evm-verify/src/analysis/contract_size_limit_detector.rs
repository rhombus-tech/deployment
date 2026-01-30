use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContractSizeLimitVulnerability {
    ExceedsLimit { description: String, location: usize, confidence: f32, size: usize },
    NearLimit { description: String, location: usize, confidence: f32, size: usize },
    OptimizationNeeded { description: String, location: usize, confidence: f32 },
}

pub struct ContractSizeLimitDetector {
    bytecode: Vec<u8>,
}

impl ContractSizeLimitDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ContractSizeLimitVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        let size = self.bytecode.len();
        let limit = 24576; // EIP-170 contract size limit (24KB)
        
        if size > limit {
            vulnerabilities.push(ContractSizeLimitVulnerability::ExceedsLimit {
                description: format!("Contract size {} exceeds limit {}", size, limit),
                location: 0,
                confidence: 1.0,
                size,
            });
        } else if size > (limit * 95 / 100) {
            vulnerabilities.push(ContractSizeLimitVulnerability::NearLimit {
                description: format!("Contract size {} is near limit {}", size, limit),
                location: 0,
                confidence: 0.85,
                size,
            });
        }
        
        vulnerabilities
    }
}
