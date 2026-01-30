use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoopUnrollingInconsistencyVulnerability {
    OptimizationInconsistency { description: String, location: usize, confidence: f32 },
}

pub struct LoopUnrollingInconsistencyDetector {
    bytecode: Vec<u8>,
}

impl LoopUnrollingInconsistencyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<LoopUnrollingInconsistencyVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_unrolled_loops() && self.has_inconsistent_logic() {
            vulnerabilities.push(LoopUnrollingInconsistencyVulnerability::OptimizationInconsistency {
                description: "Loop unrolling creates inconsistent behavior - optimization bug".to_string(),
                location: 0,
                confidence: 0.70,
            });
        }
        
        vulnerabilities
    }
    
    fn has_unrolled_loops(&self) -> bool {
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        let dup_count = self.bytecode.iter().filter(|&&b| b >= 0x80 && b <= 0x8F).count();
        jumpi_count < 2 && dup_count > 10
    }
    
    fn has_inconsistent_logic(&self) -> bool {
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        eq_count > 5
    }
}
