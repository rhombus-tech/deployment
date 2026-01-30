use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoleHierarchyViolationVulnerability {
    RoleEscalation {
        description: String,
        location: usize,
        from_role: String,
        to_role: String,
        confidence: f32,
    },
    MissingHierarchyCheck {
        description: String,
        location: usize,
    },
}

pub struct RoleHierarchyViolationDetector {
    bytecode: Vec<u8>,
}

impl RoleHierarchyViolationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<RoleHierarchyViolationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.is_role_grant_function(i) {
                let checks_hierarchy = self.validates_role_hierarchy(i, i + 150);
                
                if !checks_hierarchy {
                    vulnerabilities.push(RoleHierarchyViolationVulnerability::MissingHierarchyCheck {
                        description: "Role can be granted without hierarchy validation".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_role_grant_function(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        self.bytecode[location..location + 20].windows(4).any(|w| {
            w[0] == 0x63 && w[1] == 0x2f && w[2] == 0x2f
        })
    }
    
    fn validates_role_hierarchy(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        self.bytecode[start..range_end].windows(8).any(|w| {
            w.iter().filter(|&&b| b == 0x54).count() >= 2
        })
    }
}
