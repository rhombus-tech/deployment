use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SymbioticNetworkDualStakingVulnerability {
    DoubleRewardClaiming { description: String, location: usize, confidence: f32 },
    UnsynchronizedStakingState { description: String, location: usize, confidence: f32 },
    DualWithdrawalExploit { description: String, location: usize, confidence: f32 },
}

pub struct SymbioticNetworkDualStakingDetector {
    bytecode: Vec<u8>,
}

impl SymbioticNetworkDualStakingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SymbioticNetworkDualStakingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.distributes_rewards() && !self.tracks_dual_claims() {
            vulnerabilities.push(SymbioticNetworkDualStakingVulnerability::DoubleRewardClaiming {
                description: "Dual staking rewards without claim tracking - double claim exploit".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.manages_stake() && !self.synchronizes_state() {
            vulnerabilities.push(SymbioticNetworkDualStakingVulnerability::UnsynchronizedStakingState {
                description: "Dual staking state without synchronization - state inconsistency".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.processes_withdrawal() && !self.checks_both_networks() {
            vulnerabilities.push(SymbioticNetworkDualStakingVulnerability::DualWithdrawalExploit {
                description: "Withdrawal without dual-network validation - withdrawal from both".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn distributes_rewards(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        call_count > 2 && add_count > 3
    }
    
    fn tracks_dual_claims(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        sload_count > 5 && sstore_count > 4 && iszero_count > 2
    }
    
    fn manages_stake(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        sstore_count > 4 && add_count > 2
    }
    
    fn synchronizes_state(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xFA).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        call_count > 3 && sload_count > 6 && eq_count > 4
    }
    
    fn processes_withdrawal(&self) -> bool {
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        sub_count > 1 && sstore_count > 3 && call_count > 1
    }
    
    fn checks_both_networks(&self) -> bool {
        let staticcall_count = self.bytecode.iter().filter(|&&b| b == 0xFA).count();
        let iszero_count = self.bytecode.iter().filter(|&&b| b == 0x15).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        staticcall_count > 2 && iszero_count > 3 && jumpi_count > 4
    }
}
