use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BalancerWeightedPoolRateVulnerability {
    WeightGradientExploit { description: String, location: usize, confidence: f32 },
}

pub struct BalancerWeightedPoolRateDetector {
    bytecode: Vec<u8>,
}

impl BalancerWeightedPoolRateDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BalancerWeightedPoolRateVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_weighted_pool_math() && !self.has_weight_validation() {
            vulnerabilities.push(BalancerWeightedPoolRateVulnerability::WeightGradientExploit {
                description: "Balancer weighted pool weight gradient can be exploited".to_string(),
                location: 0,
                confidence: 0.75,
            });
        }
        
        vulnerabilities
    }
    
    fn has_weighted_pool_math(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let exp_count = self.bytecode.iter().filter(|&&b| b == 0x0A).count();
        mul_count > 4 && exp_count > 0
    }
    
    fn has_weight_validation(&self) -> bool {
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        lt_count > 3
    }
}
