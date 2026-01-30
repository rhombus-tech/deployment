use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimelockFrontrunVulnerability {
    ExecutableBeforeTimelock { description: String, location: usize, confidence: f32 },
    TimelockNotEnforced { description: String, location: usize },
    QueueAndExecuteSameBlock { description: String, location: usize },
}

pub struct TimelockFrontrunDetector {
    bytecode: Vec<u8>,
}

impl TimelockFrontrunDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TimelockFrontrunVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_execute_function(i) {
                if !self.validates_timelock_delay(i, i + 100) {
                    vulnerabilities.push(TimelockFrontrunVulnerability::TimelockNotEnforced {
                        description: "execute() without timelock delay validation - frontrunnable".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_execute_function(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        // execute selector: 0x1cff79cd
        self.bytecode[location..location + 20]
            .windows(4)
            .any(|w| w == [0x1c, 0xff, 0x79, 0xcd])
    }
    
    fn validates_timelock_delay(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Must check: block.timestamp >= queuedTime + delay
        let has_timestamp = self.bytecode[start..range_end].iter().any(|&b| b == 0x42);
        let has_add = self.bytecode[start..range_end].iter().any(|&b| b == 0x01);
        let has_comparison = self.bytecode[start..range_end].iter().any(|&b| b == 0x10 || b == 0x11);
        
        has_timestamp && has_add && has_comparison
    }
}
