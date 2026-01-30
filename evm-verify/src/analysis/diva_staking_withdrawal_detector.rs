use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DivaStakingWithdrawalVulnerability {
    WithdrawalDelayManipulation { description: String, location: usize, confidence: f32 },
    UnstakingQueueExploit { description: String, location: usize, confidence: f32 },
    PartialWithdrawalAttack { description: String, location: usize, confidence: f32 },
}

pub struct DivaStakingWithdrawalDetector {
    bytecode: Vec<u8>,
}

impl DivaStakingWithdrawalDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DivaStakingWithdrawalVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.processes_withdrawal() && !self.enforces_delay() {
            vulnerabilities.push(DivaStakingWithdrawalVulnerability::WithdrawalDelayManipulation {
                description: "Withdrawal without delay enforcement - instant unstaking exploit".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.manages_queue() && !self.validates_order() {
            vulnerabilities.push(DivaStakingWithdrawalVulnerability::UnstakingQueueExploit {
                description: "Unstaking queue without order validation - queue manipulation".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.allows_partial_withdrawal() && !self.checks_minimum() {
            vulnerabilities.push(DivaStakingWithdrawalVulnerability::PartialWithdrawalAttack {
                description: "Partial withdrawal without minimum check - dust attack".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn processes_withdrawal(&self) -> bool {
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        call_count > 1 && sub_count > 1
    }
    
    fn enforces_delay(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        timestamp_count > 0 && sload_count > 3 && gt_count > 1
    }
    
    fn manages_queue(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        sstore_count > 4 && add_count > 2
    }
    
    fn validates_order(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        sload_count > 5 && eq_count > 3
    }
    
    fn allows_partial_withdrawal(&self) -> bool {
        let div_count = self.bytecode.iter().filter(|&&b| b == 0x04).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        div_count > 1 && gt_count > 1
    }
    
    fn checks_minimum(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let gt_count = self.bytecode.iter().filter(|&&b| b == 0x11).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        sload_count > 2 && gt_count > 2 && jumpi_count > 2
    }
}
