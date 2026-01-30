use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoleRenounceLockoutVulnerability {
    IrrevocableRoleRenouncement { description: String, location: usize, confidence: f32 },
    SingleAdminLockout { description: String, location: usize, confidence: f32 },
    EmergencyRecoveryMissing { description: String, location: usize, confidence: f32 },
}

pub struct RoleRenounceLockoutDetector {
    bytecode: Vec<u8>,
}

impl RoleRenounceLockoutDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<RoleRenounceLockoutVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        if self.allows_role_renouncement() && !self.has_role_recovery() {
            vulnerabilities.push(RoleRenounceLockoutVulnerability::IrrevocableRoleRenouncement {
                description: "Role renouncement without recovery mechanism - permanent lockout risk".to_string(),
                location: 0,
                confidence: 0.90,
            });
        }
        
        if self.has_single_admin_pattern() && self.allows_self_renouncement() {
            vulnerabilities.push(RoleRenounceLockoutVulnerability::SingleAdminLockout {
                description: "Single admin can renounce role - contract lockout possible".to_string(),
                location: 0,
                confidence: 0.85,
            });
        }
        
        if self.has_critical_functions() && !self.has_emergency_access() {
            vulnerabilities.push(RoleRenounceLockoutVulnerability::EmergencyRecoveryMissing {
                description: "Critical functions with no emergency access - irrecoverable lockout".to_string(),
                location: 0,
                confidence: 0.80,
            });
        }
        
        vulnerabilities
    }
    
    fn allows_role_renouncement(&self) -> bool {
        // Pattern: caller removes their own role
        let caller_count = self.bytecode.iter().filter(|&&b| b == 0x33).count(); // CALLER
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        caller_count > 1 && sstore_count > 2
    }
    
    fn has_role_recovery(&self) -> bool {
        // Check for timelock or multi-sig recovery
        let timestamp_count = self.bytecode.iter().filter(|&&b| b == 0x42).count();
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1 || b == 0xF4).count();
        timestamp_count > 2 || call_count > 3
    }
    
    fn has_single_admin_pattern(&self) -> bool {
        // Single storage slot for admin role
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let eq_count = self.bytecode.iter().filter(|&&b| b == 0x14).count();
        sload_count > 2 && eq_count > 3
    }
    
    fn allows_self_renouncement(&self) -> bool {
        let caller_count = self.bytecode.iter().filter(|&&b| b == 0x33).count();
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        caller_count > 0 && sstore_count > 1
    }
    
    fn has_critical_functions(&self) -> bool {
        // Functions that modify state significantly
        let sstore_count = self.bytecode.iter().filter(|&&b| b == 0x55).count();
        let call_count = self.bytecode.iter().filter(|&&b| b == 0xF1).count();
        sstore_count > 5 || call_count > 3
    }
    
    fn has_emergency_access(&self) -> bool {
        // Multiple admin addresses or recovery mechanism
        let sload_count = self.bytecode.iter().filter(|&&b| b == 0x54).count();
        let or_count = self.bytecode.iter().filter(|&&b| b == 0x17).count();
        sload_count > 5 && or_count > 1
    }
}
