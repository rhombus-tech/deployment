use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScrollL1MessageQueueVulnerability {
    MessageQueueCensorship { description: String, location: usize, confidence: f32 },
    QueueOverflowExploit { description: String, location: usize, confidence: f32 },
    MessageReorderingAttack { description: String, location: usize, confidence: f32 },
}

pub struct ScrollL1MessageQueueDetector {
    bytecode: Vec<u8>,
}

impl ScrollL1MessageQueueDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ScrollL1MessageQueueVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.manages_message_queue() && !self.enforces_inclusion() {
            vulnerabilities.push(ScrollL1MessageQueueVulnerability::MessageQueueCensorship {
                description: "Message queue without forced inclusion - sequencer censorship".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.appends_to_queue() && !self.checks_queue_limit() {
            vulnerabilities.push(ScrollL1MessageQueueVulnerability::QueueOverflowExploit {
                description: "Queue append without size limit - DoS via queue overflow".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.processes_queue() && !self.validates_order() {
            vulnerabilities.push(ScrollL1MessageQueueVulnerability::MessageReorderingAttack {
                description: "Message processing without order validation - message reordering".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn manages_message_queue(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        sstore_count > 4 && sload_count > 5
    }
    
    fn enforces_inclusion(&self) -> bool {
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        timestamp_count > 0 && lt_count > 2 && jumpi_count > 3
    }
    
    fn appends_to_queue(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        sstore_count > 3 && add_count > 2
    }
    
    fn checks_queue_limit(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let lt_count = self.bytecode.iter().filter(|&&b| b == 0x10).count();
        let jumpi_count = self.bytecode.iter().filter(|&&b| b == 0x57).count();
        sload_count > 4 && lt_count > 1 && jumpi_count > 2
    }
    
    fn processes_queue(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xFA).count();
        sload_count > 5 && call_count > 2
    }
    
    fn validates_order(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        sload_count > 6 && eq_count > 3 && add_count > 2
    }
}
