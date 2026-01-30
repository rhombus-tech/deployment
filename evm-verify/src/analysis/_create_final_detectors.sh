#!/bin/bash

# Create remaining critical detectors

cat > role_hierarchy_violation_detector.rs << 'EOFROLE'
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
EOFROLE

cat > builder_exclusive_orderflow_detector.rs << 'EOFBUILDER'
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BuilderExclusiveOrderflowVulnerability {
    ExclusiveOrderflowRisk {
        description: String,
        location: usize,
        confidence: f32,
    },
    BuilderCentralization {
        description: String,
        location: usize,
    },
}

pub struct BuilderExclusiveOrderflowDetector {
    bytecode: Vec<u8>,
}

impl BuilderExclusiveOrderflowDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<BuilderExclusiveOrderflowVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.has_builder_address_check(i) {
                let is_exclusive = self.enforces_exclusive_builder(i, i + 100);
                
                if is_exclusive {
                    vulnerabilities.push(BuilderExclusiveOrderflowVulnerability::ExclusiveOrderflowRisk {
                        description: "Transaction restricted to specific builder - censorship risk".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn has_builder_address_check(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        self.bytecode[location..location + 30].iter().any(|&b| b == 0x41)
    }
    
    fn enforces_exclusive_builder(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        self.bytecode[start..range_end].windows(3).any(|w| {
            w[0] == 0x41 && w[1] == 0x14 && w[2] == 0xfd
        })
    }
}
EOFBUILDER

echo "✅ Created final batch of detectors"
