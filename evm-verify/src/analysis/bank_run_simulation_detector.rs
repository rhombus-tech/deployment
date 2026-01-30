use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BankRunSimulationVulnerability {
    WithdrawalQueueOverflow { description: String, location: usize, confidence: f32 },
}

pub struct BankRunSimulationDetector {
    bytecode: Vec<u8>,
}

impl BankRunSimulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BankRunSimulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.has_withdrawal_queue() && !self.has_queue_limits() {
            vulnerabilities.push(BankRunSimulationVulnerability::WithdrawalQueueOverflow {
                description: "Withdrawal queue without size limits - bank run overflow risk".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        vulnerabilities
    }
    
    fn has_withdrawal_queue(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        sstore_count > 3 && add_count > 2
    }
    
    fn has_queue_limits(&self) -> bool {
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        lt_count > 2
    }
}
