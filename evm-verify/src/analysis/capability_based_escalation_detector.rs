use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Capability-Based Permission Escalation Detection
/// 
/// Detects privilege escalation via capability delegation:
/// 1. Capabilities can be transferred without restriction
/// 2. Capability inheritance allows escalation
/// 3. Delegated capabilities exceed original permissions
/// 4. Capability revocation not enforced
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CapabilityBasedEscalationVulnerability {
    /// Critical: Unrestricted capability transfer
    UnrestrictedCapabilityTransfer {
        description: String,
        location: usize,
        capability_type: String,
        confidence: f32,
    },
    /// High: Capability delegation exceeds original permissions
    CapabilityDelegationExceedsPermissions {
        description: String,
        delegation_location: usize,
        original_permissions: Vec<String>,
        delegated_permissions: Vec<String>,
    },
    /// High: No expiration on delegated capabilities
    NoCapabilityExpiration {
        description: String,
        location: usize,
    },
    /// Medium: Revocation not properly enforced
    RevocationNotEnforced {
        description: String,
        location: usize,
    },
}

pub struct CapabilityBasedEscalationDetector {
    bytecode: Vec<u8>,
}

impl CapabilityBasedEscalationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CapabilityBasedEscalationVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Find capability delegation functions
        let delegation_functions = self.find_capability_delegation_functions();
        
        for (location, cap_type) in delegation_functions {
            // Pattern 1: Check for transfer restrictions
            let has_restrictions = self.has_delegation_restrictions(location, location + 150);
            
            if !has_restrictions {
                vulnerabilities.push(CapabilityBasedEscalationVulnerability::UnrestrictedCapabilityTransfer {
                    description: format!("Capability '{}' can be delegated without restrictions", cap_type),
                    location,
                    capability_type: cap_type.clone(),
                    confidence: 0.85,
                });
            }
            
            // Pattern 2: Check if delegated permissions exceed original
            let (original_perms, delegated_perms) = self.analyze_permission_delegation(location, location + 200);
            
            if delegated_perms.len() > original_perms.len() {
                vulnerabilities.push(CapabilityBasedEscalationVulnerability::CapabilityDelegationExceedsPermissions {
                    description: "Delegated capabilities exceed original permissions".to_string(),
                    delegation_location: location,
                    original_permissions: original_perms,
                    delegated_permissions: delegated_perms,
                });
            }
            
            // Pattern 3: Check for expiration mechanism
            let has_expiration = self.has_expiration_mechanism(location, location + 150);
            
            if !has_expiration {
                vulnerabilities.push(CapabilityBasedEscalationVulnerability::NoCapabilityExpiration {
                    description: "Delegated capability has no expiration time".to_string(),
                    location,
                });
            }
        }
        
        // Pattern 4: Check revocation enforcement
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_revocation_function(i) {
                let properly_enforced = self.revocation_properly_enforced(i, i + 100);
                
                if !properly_enforced {
                    vulnerabilities.push(CapabilityBasedEscalationVulnerability::RevocationNotEnforced {
                        description: "Capability revocation not enforced in all code paths".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_capability_delegation_functions(&self) -> Vec<(usize, String)> {
        let mut delegations = Vec::new();
        
        // Look for delegation-related function selectors
        // delegate(), approve(), grantRole(), etc.
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 { // PUSH4 (function selector)
                if i + 4 < self.bytecode.len() {
                    let selector = &self.bytecode[i+1..i+5];
                    
                    // Common delegation selectors
                    if self.is_delegation_selector(selector) {
                        let cap_type = self.identify_capability_type(i, i + 100);
                        delegations.push((i, cap_type));
                    }
                }
            }
        }
        
        delegations
    }
    
    fn is_delegation_selector(&self, selector: &[u8]) -> bool {
        // delegate(): 0x5c19a95c
        // approve(): 0x095ea7b3
        // grantRole(): 0x2f2ff15d
        // setApprovalForAll(): 0xa22cb465
        
        matches!(selector,
            [0x5c, 0x19, 0xa9, 0x5c] | // delegate
            [0x09, 0x5e, 0xa7, 0xb3] | // approve
            [0x2f, 0x2f, 0xf1, 0x5d] | // grantRole
            [0xa2, 0x2c, 0xb4, 0x65]   // setApprovalForAll
        )
    }
    
    fn identify_capability_type(&self, start: usize, end: usize) -> String {
        let range_end = end.min(self.bytecode.len());
        
        // Try to identify what type of capability is being delegated
        // by looking at the surrounding logic
        
        if self.bytecode[start..range_end].iter().any(|&b| b == 0x2f) {
            return "role_based".to_string();
        }
        
        if self.bytecode[start..range_end].windows(4).any(|w| w[0] == 0x63 && w[1] == 0xa9) {
            return "token_approval".to_string();
        }
        
        "unknown".to_string()
    }
    
    fn has_delegation_restrictions(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Restrictions include:
        // 1. Whitelist check
        // 2. Amount/permission limit
        // 3. Time-based restrictions
        
        let has_whitelist = self.bytecode[start..range_end]
            .windows(5)
            .any(|w| {
                w.iter().any(|&b| b == 0x54) && // SLOAD (whitelist check)
                w.iter().any(|&b| b == 0x14)    // EQ
            });
        
        let has_limit_check = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x10 || b == 0x11); // LT or GT
        
        let has_time_restriction = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x42); // TIMESTAMP
        
        has_whitelist || has_limit_check || has_time_restriction
    }
    
    fn analyze_permission_delegation(&self, start: usize, end: usize) -> (Vec<String>, Vec<String>) {
        let range_end = end.min(self.bytecode.len());
        
        let mut original_permissions = Vec::new();
        let mut delegated_permissions = Vec::new();
        
        if start >= range_end {
            return (original_permissions, delegated_permissions);
        }
        
        // Count permission-granting operations before and after delegation
        
        // Original permissions: SLOAD operations before delegation
        let original_count = self.bytecode[start..start + 50.min(range_end - start)]
            .iter()
            .filter(|&&b| b == 0x54) // SLOAD
            .count();
        
        // Delegated permissions: SSTORE operations (granting new permissions)
        let delegated_count = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b == 0x55) // SSTORE
            .count();
        
        // Populate with placeholder names based on counts
        for i in 0..original_count {
            original_permissions.push(format!("permission_{}", i));
        }
        
        for i in 0..delegated_count {
            delegated_permissions.push(format!("delegated_permission_{}", i));
        }
        
        (original_permissions, delegated_permissions)
    }
    
    fn has_expiration_mechanism(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Expiration mechanism:
        // 1. TIMESTAMP used in delegation
        // 2. Expiry time stored
        // 3. Checks in capability use
        
        let stores_timestamp = self.bytecode[start..range_end]
            .windows(3)
            .any(|w| {
                w[0] == 0x42 && // TIMESTAMP
                w.iter().skip(1).any(|&b| b == 0x55) // SSTORE
            });
        
        let has_expiry_check = self.bytecode[start..range_end]
            .windows(4)
            .any(|w| {
                w[0] == 0x42 && // TIMESTAMP
                (w[1] == 0x10 || w[1] == 0x11) && // LT or GT
                w.iter().any(|&b| b == 0xfd) // REVERT if expired
            });
        
        stores_timestamp && has_expiry_check
    }
    
    fn is_revocation_function(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // revoke(), revokeRole(), etc.
        // Selectors: 0xd547741f (revokeRole)
        
        self.bytecode[location..location + 30].windows(4).any(|w| {
            w[0] == 0x63 && w[1] == 0xd5 && w[2] == 0x47 && w[3] == 0x74
        })
    }
    
    fn revocation_properly_enforced(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Proper revocation:
        // 1. Capability storage is zeroed/deleted
        // 2. Event is emitted
        // 3. All copies/references are cleared
        
        let has_storage_clear = self.bytecode[start..range_end]
            .windows(3)
            .any(|w| {
                w[0] == 0x60 && w[1] == 0x00 && w[2] == 0x55 // PUSH1 0, SSTORE (clear)
            });
        
        let has_event = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b >= 0xa0 && b <= 0xa4); // LOG0-LOG4
        
        let clears_multiple_slots = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b == 0x55) // SSTORE
            .count() >= 2;
        
        has_storage_clear && has_event && clears_multiple_slots
    }
}
