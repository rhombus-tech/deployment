use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PermitDeadlineManipulationVulnerability {
    NoDeadlineValidation {
        description: String,
        permit_location: usize,
        confidence: f32,
    },
    DeadlineTooLong {
        description: String,
        location: usize,
        deadline_value: u64,
    },
    DeadlineFrontrunnable {
        description: String,
        location: usize,
    },
}

pub struct PermitDeadlineManipulationDetector {
    bytecode: Vec<u8>,
}

impl PermitDeadlineManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<PermitDeadlineManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.is_permit_function(i) {
                let validates_deadline = self.validates_deadline_properly(i, i + 150);
                
                if !validates_deadline {
                    vulnerabilities.push(PermitDeadlineManipulationVulnerability::NoDeadlineValidation {
                        description: "Permit deadline not validated against block.timestamp".to_string(),
                        permit_location: i,
                        confidence: 0.90,
                    });
                }
                
                if let Some(deadline) = self.extract_deadline_value(i, i + 150) {
                    if deadline > 365 * 24 * 3600 {
                        vulnerabilities.push(PermitDeadlineManipulationVulnerability::DeadlineTooLong {
                            description: format!("Permit deadline of {} seconds is excessive", deadline),
                            location: i,
                            deadline_value: deadline,
                        });
                    }
                }
                
                let is_frontrunnable = self.permit_is_frontrunnable(i, i + 150);
                if is_frontrunnable {
                    vulnerabilities.push(PermitDeadlineManipulationVulnerability::DeadlineFrontrunnable {
                        description: "Permit can be frontrun due to long deadline window".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_permit_function(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        self.bytecode[location..location + 30].windows(4).any(|w| {
            w[0] == 0x63 && w[1] == 0xd5 && w[2] == 0x05 && w[3] == 0xac // permit selector
        })
    }
    
    fn validates_deadline_properly(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        self.bytecode[start..range_end].windows(4).any(|w| {
            w[0] == 0x42 && w[1] == 0x11 && w[2] == 0x15 && w[3] == 0xfd
        })
    }
    
    fn extract_deadline_value(&self, start: usize, end: usize) -> Option<u64> {
        let range_end = end.min(self.bytecode.len());
        
        for i in start..range_end {
            if self.bytecode[i] == 0x61 && i + 2 < range_end {
                return Some(((self.bytecode[i+1] as u64) << 8) | self.bytecode[i+2] as u64);
            }
        }
        None
    }
    
    fn permit_is_frontrunnable(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        !self.bytecode[start..range_end].iter().any(|&b| b == 0x31)
    }
}
