use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionOrderingVulnerability {
    Critical { description: String, location: usize },
    High { description: String, location: usize },
    Medium { description: String, location: usize },
}

pub struct TransactionOrderingDetector {
    bytecode: Vec<u8>,
}

impl TransactionOrderingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TransactionOrderingVulnerability> {
        
        let mut vulnerabilities = Vec::new();
        // MEV-vulnerable transaction ordering
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x3a { // GASPRICE
                let affects_execution = self.bytecode[i..i+30]
                    .iter()
                    .any(|&b| b == 0x57); // JUMPI
                if affects_execution {
                    vulnerabilities.push(TransactionOrderingVulnerability::Medium {
                        description: "Execution depends on gas price (MEV risk)".to_string(),
                        location: i,
                    });
                }
            }
        }
        vulnerabilities
    
    }
}
