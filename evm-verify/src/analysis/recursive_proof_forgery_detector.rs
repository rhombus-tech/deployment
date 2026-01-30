use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecursiveProofForgeryVulnerability {
    NestedProofBypass { description: String, location: usize, confidence: f32 },
    RecursionDepthExploit { description: String, location: usize },
}

pub struct RecursiveProofForgeryDetector {
    bytecode: Vec<u8>,
}

impl RecursiveProofForgeryDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<RecursiveProofForgeryVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_recursive_verification() && !self.checks_recursion_depth() {
            vulnerabilities.push(RecursiveProofForgeryVulnerability::NestedProofBypass {
                description: "Recursive proof verification without depth limit - forgery risk".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn has_recursive_verification(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        call_count > 3
    }
    
    fn checks_recursion_depth(&self) -> bool {
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        gt_count > 2
    }
}
