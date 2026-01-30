use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainlinkCcipMessageOrderingVulnerability {
    MessageReordering { description: String, location: usize, confidence: f32 },
    SequenceNumberSkip { description: String, location: usize, confidence: f32 },
    NonceManipulation { description: String, location: usize, confidence: f32 },
}

pub struct ChainlinkCcipMessageOrderingDetector {
    bytecode: Vec<u8>,
}

impl ChainlinkCcipMessageOrderingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ChainlinkCcipMessageOrderingVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.processes_messages() && !self.validates_sequence() {
            vulnerabilities.push(ChainlinkCcipMessageOrderingVulnerability::MessageReordering {
                description: "Message processing without sequence validation - reordering attack".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.uses_sequence_number() && !self.checks_continuity() {
            vulnerabilities.push(ChainlinkCcipMessageOrderingVulnerability::SequenceNumberSkip {
                description: "Sequence number without continuity check - message skip".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.tracks_nonce() && !self.validates_increment() {
            vulnerabilities.push(ChainlinkCcipMessageOrderingVulnerability::NonceManipulation {
                description: "Nonce tracking without increment validation - nonce manipulation".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn processes_messages(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xFA).count();
        sload_count > 4 && call_count > 2
    }
    
    fn validates_sequence(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        sload_count > 5 && eq_count > 3
    }
    
    fn uses_sequence_number(&self) -> bool {
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        sload_count > 3 && add_count > 1
    }
    
    fn checks_continuity(&self) -> bool {
        let sub_count = self.bytecode.iter().filter(|&&b| b == 0x03).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        sub_count > 1 && eq_count > 2
    }
    
    fn tracks_nonce(&self) -> bool {
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        sstore_count > 2 && sload_count > 3
    }
    
    fn validates_increment(&self) -> bool {
        let add_count = self.bytecode.iter().filter(|&&b| b == 0x01).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        add_count > 1 && eq_count > 2
    }
}
