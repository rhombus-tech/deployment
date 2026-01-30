use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MissingCriticalEventsVulnerability {
    StateChangeWithoutEvent { description: String, location: usize, confidence: f32 },
    OwnershipTransferNoEvent { description: String, location: usize },
    BalanceChangeNoEvent { description: String, location: usize },
}

pub struct MissingCriticalEventsDetector {
    bytecode: Vec<u8>,
}

impl MissingCriticalEventsDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MissingCriticalEventsVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x55 { // SSTORE (state change)
                if !self.has_event_after(i, i + 50) {
                    vulnerabilities.push(MissingCriticalEventsVulnerability::StateChangeWithoutEvent {
                        description: "Critical state change without event emission - transparency issue".to_string(),
                        location: i,
                        confidence: 0.75,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_event_after(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        // LOG0-LOG4 opcodes (0xA0-0xA4)
        self.bytecode[start..range_end].iter().any(|&b| b >= 0xA0 && b <= 0xA4)
    }
}
