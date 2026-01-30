use serde::{Deserialize, Serialize};

/// Timelock Bypass Vulnerability Detection
/// 
/// Detects patterns where timelock delays can be bypassed:
/// 1. Emergency/admin functions bypassing timelock
/// 2. Direct state changes without queuing
/// 3. Timelock cancelation without proper checks
/// 4. Guardian role bypassing timelock delays
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimelockBypassVulnerability {
    /// Critical: Emergency function bypasses timelock
    EmergencyBypass {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// Critical: Direct state modification bypassing queue
    DirectStateBypass {
        description: String,
        location: usize,
        bypass_type: String,
    },
    /// High: Timelock cancelation without proper authorization
    UnauthorizedCancelation {
        description: String,
        location: usize,
    },
    /// High: Guardian role with excessive bypass permissions
    GuardianOverreach {
        description: String,
        location: usize,
        permissions: Vec<String>,
    },
}

pub struct TimelockBypassDetector {
    bytecode: Vec<u8>,
}

impl TimelockBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<TimelockBypassVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Emergency functions that bypass timelock
        // Look for: onlyEmergency modifier + SSTORE without delay check
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_emergency_function(i) {
                let has_timelock_check = self.has_timelock_delay_check(i, i + 100);
                let modifies_state = self.modifies_critical_state(i, i + 100);
                
                if !has_timelock_check && modifies_state {
                    vulnerabilities.push(TimelockBypassVulnerability::EmergencyBypass {
                        description: "Emergency function modifies state without timelock delay".to_string(),
                        location: i,
                        confidence: 0.85,
                    });
                }
            }
        }
        
        // Pattern 2: Direct SSTORE to critical slots without queue/execute pattern
        let critical_slots = self.identify_critical_storage_slots();
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x55 { // SSTORE
                let slot = self.get_storage_slot_at(i);
                
                if critical_slots.contains(&slot) {
                    // Check if this SSTORE is within a timelock queue/execute flow
                    let in_timelock_flow = self.is_in_timelock_flow(i);
                    
                    if !in_timelock_flow {
                        let bypass_type = self.classify_bypass_type(i);
                        vulnerabilities.push(TimelockBypassVulnerability::DirectStateBypass {
                            description: format!(
                                "Critical storage slot {} modified without timelock - bypass type: {}",
                                slot, bypass_type
                            ),
                            location: i,
                            bypass_type,
                        });
                    }
                }
            }
        }
        
        // Pattern 3: Timelock cancelation functions
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.is_cancel_function(i) {
                let has_proper_auth = self.has_multisig_or_governance_check(i, i + 80);
                
                if !has_proper_auth {
                    vulnerabilities.push(TimelockBypassVulnerability::UnauthorizedCancelation {
                        description: "Timelock cancel function lacks proper authorization".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 4: Guardian roles with bypass permissions
        let guardian_functions = self.find_guardian_functions();
        for (location, permissions) in guardian_functions {
            if permissions.len() > 3 { // Too many bypass permissions
                vulnerabilities.push(TimelockBypassVulnerability::GuardianOverreach {
                    description: "Guardian role has excessive bypass permissions".to_string(),
                    location,
                    permissions: permissions.clone(),
                });
            }
        }
        
        vulnerabilities
    }
    
    fn is_emergency_function(&self, location: usize) -> bool {
        // Check for emergency modifier patterns:
        // 1. Function selector for emergency functions
        // 2. Role check for EMERGENCY_ROLE
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        // Look for emergency role constant (keccak256("EMERGENCY_ROLE"))
        self.bytecode[location..location + 20]
            .windows(4)
            .any(|w| {
                // Emergency role patterns
                w[0] == 0x60 && w[1] > 0x00 && // PUSH
                self.bytecode.get(location + 10).map_or(false, |&b| b == 0x54 || b == 0x14) // SLOAD or EQ
            })
    }
    
    fn has_timelock_delay_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Check for timestamp comparison (TIMESTAMP + LT/GT)
        self.bytecode[start..range_end]
            .windows(5)
            .any(|w| {
                (w[0] == 0x42 || w[0] == 0x43) && // TIMESTAMP or NUMBER
                (w.contains(&0x10) || w.contains(&0x11) || w.contains(&0x12)) // LT, GT, SLT
            })
    }
    
    fn modifies_critical_state(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Check for SSTORE, CALL, DELEGATECALL
        self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x55 || b == 0xf1 || b == 0xf4)
    }
    
    fn identify_critical_storage_slots(&self) -> Vec<u8> {
        let mut slots = Vec::new();
        
        // Common critical slots:
        // - Owner/admin slots
        // - Timelock delay slots
        // - Paused state slots
        // Usually stored in low slot numbers or at specific keccak256 positions
        
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x55 { // SSTORE
                if i > 2 {
                    // Get the slot being stored to
                    if self.bytecode[i-2] == 0x60 { // PUSH1
                        let slot = self.bytecode[i-1];
                        if slot < 10 { // Low slots are often critical
                            slots.push(slot);
                        }
                    }
                }
            }
        }
        
        slots.sort();
        slots.dedup();
        slots
    }
    
    fn get_storage_slot_at(&self, location: usize) -> u8 {
        if location > 2 && self.bytecode[location - 2] == 0x60 {
            self.bytecode[location - 1]
        } else {
            0
        }
    }
    
    fn is_in_timelock_flow(&self, location: usize) -> bool {
        // Check if this operation is part of a queue->execute flow
        // Look backwards for queueTransaction or executeTransaction patterns
        let search_start = location.saturating_sub(200);
        
        self.bytecode[search_start..location]
            .windows(4)
            .any(|w| {
                // Queue/execute function selectors
                (w[0] == 0x63 && w[1] == 0x3a) || // queueTransaction
                (w[0] == 0x63 && w[1] == 0x0e)    // executeTransaction
            })
    }
    
    fn classify_bypass_type(&self, location: usize) -> String {
        let search_range = location.saturating_sub(50)..location.saturating_add(10).min(self.bytecode.len());
        
        if self.bytecode[search_range.clone()].iter().any(|&b| b == 0x33) {
            return "admin_direct".to_string();
        }
        if self.bytecode[search_range].iter().any(|&b| b == 0xfd) {
            return "revert_bypass".to_string();
        }
        "unknown".to_string()
    }
    
    fn is_cancel_function(&self, location: usize) -> bool {
        // Look for cancel function selector patterns
        if location + 4 > self.bytecode.len() {
            return false;
        }
        
        // Common cancel selectors: 0xc4d252f5 (cancelTransaction)
        self.bytecode[location] == 0x63 && 
        self.bytecode[location + 1] == 0xc4
    }
    
    fn has_multisig_or_governance_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Check for multiple CALLER checks or role verification
        let caller_checks = self.bytecode[start..range_end]
            .iter()
            .filter(|&&b| b == 0x33) // CALLER
            .count();
        
        caller_checks >= 2 || // Multiple caller checks suggest multisig
        self.bytecode[start..range_end].iter().any(|&b| b == 0x14) // EQ for role check
    }
    
    fn find_guardian_functions(&self) -> Vec<(usize, Vec<String>)> {
        let mut guardian_functions = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_guardian_function(i) {
                let permissions = self.extract_guardian_permissions(i, i + 100);
                if !permissions.is_empty() {
                    guardian_functions.push((i, permissions));
                }
            }
        }
        
        guardian_functions
    }
    
    fn is_guardian_function(&self, location: usize) -> bool {
        // Check for guardian role patterns
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        self.bytecode[location..location + 20]
            .windows(2)
            .any(|w| w[0] == 0x60 && w[1] > 0x00)
    }
    
    fn extract_guardian_permissions(&self, start: usize, end: usize) -> Vec<String> {
        let mut permissions = Vec::new();
        let range_end = end.min(self.bytecode.len());
        
        if start >= range_end {
            return permissions;
        }
        
        // Count critical operations that can be performed
        if self.bytecode[start..range_end].iter().any(|&b| b == 0x55) {
            permissions.push("direct_storage_write".to_string());
        }
        if self.bytecode[start..range_end].iter().any(|&b| b == 0xf1) {
            permissions.push("external_call".to_string());
        }
        if self.bytecode[start..range_end].iter().any(|&b| b == 0xf4) {
            permissions.push("delegatecall".to_string());
        }
        if self.bytecode[start..range_end].iter().any(|&b| b == 0xff) {
            permissions.push("selfdestruct".to_string());
        }
        
        permissions
    }
}
