use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GyroscopeEclpManipulationVulnerability {
    EllipticalParameterAttack { description: String, location: usize, confidence: f32 },
}

pub struct GyroscopeEclpManipulationDetector {
    bytecode: Vec<u8>,
}

impl GyroscopeEclpManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<GyroscopeEclpManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_eclp_math() && !self.validates_eclp_parameters() {
            vulnerabilities.push(GyroscopeEclpManipulationVulnerability::EllipticalParameterAttack {
                description: "Gyroscope E-CLP pool parameters can be manipulated".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn has_eclp_math(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        mul_count > 5 && div_count > 3
    }
    
    fn validates_eclp_parameters(&self) -> bool {
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        gt_count > 4
    }
}
