use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SsvNetworkClusterLiquidationVulnerability {
    InsufficientOperatorBalance { description: String, location: usize, confidence: f32 },
    ClusterLiquidationCascade { description: String, location: usize, confidence: f32 },
    UnmonitoredBurnRate { description: String, location: usize, confidence: f32 },
}

pub struct SsvNetworkClusterLiquidationDetector {
    bytecode: Vec<u8>,
}

impl SsvNetworkClusterLiquidationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SsvNetworkClusterLiquidationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.manages_ssv_cluster() && !self.monitors_operator_balance() {
            vulnerabilities.push(SsvNetworkClusterLiquidationVulnerability::InsufficientOperatorBalance {
                description: "SSV cluster without operator balance monitoring - liquidation risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.has_multiple_clusters() && !self.isolates_cluster_risk() {
            vulnerabilities.push(SsvNetworkClusterLiquidationVulnerability::ClusterLiquidationCascade {
                description: "Multiple clusters without risk isolation - cascade liquidation exposure".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.pays_operator_fees() && !self.tracks_burn_rate() {
            vulnerabilities.push(SsvNetworkClusterLiquidationVulnerability::UnmonitoredBurnRate {
                description: "Operator fee payments without burn rate tracking - unexpected liquidation".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn manages_ssv_cluster(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        call_count > 2 && sstore_count > 4
    }
    
    fn monitors_operator_balance(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        staticcall_count > 2 && lt_count > 1 && jumpi_count > 3
    }
    
    fn has_multiple_clusters(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        sload_count > 10
    }
    
    fn isolates_cluster_risk(&self) -> bool {
        // Separate state management for each cluster
        let sha3_count = self.bytecode.iter().filter(|&&b| b == 0x20).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        sha3_count > 3 && sload_count > 8
    }
    
    fn pays_operator_fees(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let mul_count = self.bytecode.iter().filter(|&&b| b == 0x02).count();
        call_count > 1 && mul_count > 3
    }
    
    fn tracks_burn_rate(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        timestamp_count > 1 && sub_count > 2 && div_count > 1
    }
}
