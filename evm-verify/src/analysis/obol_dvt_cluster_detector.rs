use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObolDvtClusterVulnerability {
    ClusterKeyManagement { description: String, location: usize, confidence: f32 },
    UnevenRewardDistribution { description: String, location: usize, confidence: f32 },
    ClusterExitCoordination { description: String, location: usize, confidence: f32 },
}

pub struct ObolDvtClusterDetector {
    bytecode: Vec<u8>,
}

impl ObolDvtClusterDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ObolDvtClusterVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.manages_cluster_keys() && !self.validates_threshold() {
            vulnerabilities.push(ObolDvtClusterVulnerability::ClusterKeyManagement {
                description: "Cluster key management without threshold validation - key compromise risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.distributes_rewards() && !self.validates_shares() {
            vulnerabilities.push(ObolDvtClusterVulnerability::UnevenRewardDistribution {
                description: "Reward distribution without share validation - unfair distribution".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.handles_exit() && !self.requires_consensus() {
            vulnerabilities.push(ObolDvtClusterVulnerability::ClusterExitCoordination {
                description: "Cluster exit without consensus - uncoordinated exit".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn manages_cluster_keys(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        sstore_count > 3 && sha3_count > 2
    }
    
    fn validates_threshold(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        sload_count > 4 && gt_count > 2
    }
    
    fn distributes_rewards(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        call_count > 2 && div_count > 1
    }
    
    fn validates_shares(&self) -> bool {
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        mul_count > 2 && eq_count > 3
    }
    
    fn handles_exit(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let log_count = self.bytecode.iter().filter(|&&b| b >= 0xA0 && b <= 0xA4).count();
        sstore_count > 3 && log_count > 1
    }
    
    fn requires_consensus(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        sload_count > 5 && eq_count > 4
    }
}
