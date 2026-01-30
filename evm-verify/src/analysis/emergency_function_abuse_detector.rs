use serde::{Serialize, Deserialize};

/// Emergency Function Abuse Detection (Platypus Finance exploit pattern)
/// 
/// Detects vulnerabilities where emergency/admin functions can be abused:
/// 1. Emergency withdraw bypassing normal checks
/// 2. Pause functions that don't actually pause everything
/// 3. Emergency functions callable during normal operation
/// 4. Admin functions without proper authorization checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmergencyFunctionAbuseVulnerability {
    /// Critical: Emergency function bypasses critical checks
    EmergencyBypassesSecurity {
        description: String,
        location: usize,
        function_selector: String,
        confidence: f32,
    },
    /// Critical: Pause doesn't actually stop operations
    IneffectivePause {
        description: String,
        location: usize,
    },
    /// High: Emergency function callable anytime
    NoEmergencyCondition {
        description: String,
        location: usize,
    },
    /// High: Admin function without access control
    MissingAccessControl {
        description: String,
        location: usize,
    },
    /// Medium: Emergency function modifies state permanently
    PermanentStateChange {
        description: String,
        location: usize,
    },
}

pub struct EmergencyFunctionAbuseDetector {
    bytecode: Vec<u8>,
}

impl EmergencyFunctionAbuseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EmergencyFunctionAbuseVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Look for "emergency" named functions
        // Common patterns: emergencyWithdraw, emergencyTransfer, emergencyPause
        // We detect by looking for function selectors that might be emergency functions
        
        // emergencyWithdraw: various selectors, we check for patterns
        for i in 0..self.bytecode.len().saturating_sub(80) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2],
                    self.bytecode[i+3], self.bytecode[i+4],
                ]);
                
                // Check if this function has emergency-like behavior
                let is_emergency_pattern = self.is_emergency_function_pattern(i);
                
                if is_emergency_pattern {
                    // Verify it has proper checks
                    let has_owner_check = self.has_owner_modifier(i);
                    let has_pause_check = self.has_pause_check(i);
                    let has_emergency_condition = self.has_emergency_condition_check(i);
                    
                    if !has_owner_check {
                        vulnerabilities.push(EmergencyFunctionAbuseVulnerability::MissingAccessControl {
                            description: format!(
                                "Emergency function (0x{:08x}) without owner check",
                                selector
                            ),
                            location: i,
                        });
                    }
                    
                    if !has_emergency_condition {
                        vulnerabilities.push(EmergencyFunctionAbuseVulnerability::NoEmergencyCondition {
                            description: format!(
                                "Emergency function (0x{:08x}) can be called anytime - no emergency state check",
                                selector
                            ),
                            location: i,
                        });
                    }
                    
                    // Check if it bypasses normal security
                    let bypasses_checks = self.bypasses_normal_checks(i);
                    if bypasses_checks {
                        vulnerabilities.push(EmergencyFunctionAbuseVulnerability::EmergencyBypassesSecurity {
                            description: "Emergency function bypasses normal withdrawal/transfer checks".to_string(),
                            location: i,
                            function_selector: format!("0x{:08x}", selector),
                            confidence: 0.85,
                        });
                    }
                }
            }
        }
        
        // Pattern 2: Check pause() and unpause() effectiveness
        let pause_loc = self.find_function_selector(0x8456cb59); // pause()
        let unpause_loc = self.find_function_selector(0x3f4ba83a); // unpause()
        
        if let Some(pause) = pause_loc {
            // Check if critical functions actually check paused state
            let critical_functions = self.find_critical_functions();
            
            for func_loc in critical_functions {
                let checks_paused = self.checks_paused_modifier(func_loc);
                
                if !checks_paused {
                    vulnerabilities.push(EmergencyFunctionAbuseVulnerability::IneffectivePause {
                        description: format!(
                            "Critical function at {} doesn't check paused state - pause is ineffective",
                            func_loc
                        ),
                        location: func_loc,
                    });
                }
            }
        }
        
        // Pattern 3: Check for Platypus-style exploit
        // Platypus had emergencyWithdraw that could drain funds
        for i in 0..self.bytecode.len().saturating_sub(60) {
            // Look for transfer patterns in emergency functions
            if self.bytecode[i] == 0xf1 { // CALL (external transfer)
                // Check if this is in an admin-protected section
                let in_admin_function = self.is_in_admin_function(i);
                
                if in_admin_function {
                    // Check if the amount is controllable
                    let amount_from_storage = self.bytecode[i.saturating_sub(30)..i]
                        .iter()
                        .any(|&b| b == 0x54); // SLOAD (reading stored amount)
                    
                    // Check if destination is controllable
                    let dest_from_calldata = self.bytecode[i.saturating_sub(30)..i]
                        .iter()
                        .any(|&b| b == 0x35); // CALLDATALOAD
                    
                    if amount_from_storage && dest_from_calldata {
                        vulnerabilities.push(EmergencyFunctionAbuseVulnerability::EmergencyBypassesSecurity {
                            description: "Admin function can transfer arbitrary amounts to arbitrary addresses - Platypus pattern".to_string(),
                            location: i,
                            function_selector: "unknown".to_string(),
                            confidence: 0.80,
                        });
                    }
                }
            }
        }
        
        // Pattern 4: Check for state changes in emergency functions
        for i in 0..self.bytecode.len().saturating_sub(70) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2],
                    self.bytecode[i+3], self.bytecode[i+4],
                ]);
                
                if self.is_emergency_function_pattern(i) {
                    // Count SSTORE operations (state changes)
                    let sstore_count = self.bytecode[i..std::cmp::min(i+70, self.bytecode.len())]
                        .iter()
                        .filter(|&&b| b == 0x55)
                        .count();
                    
                    if sstore_count > 3 {
                        vulnerabilities.push(EmergencyFunctionAbuseVulnerability::PermanentStateChange {
                            description: format!(
                                "Emergency function (0x{:08x}) makes {} state changes - may be irreversible",
                                selector, sstore_count
                            ),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 5: Check for rescue functions that bypass normal flow
        // rescueTokens, rescueFunds, etc.
        for i in 0..self.bytecode.len().saturating_sub(50) {
            // Look for token transfer patterns
            // transferFrom selector: 0x23b872dd
            if self.bytecode[i] == 0x63 && 
               i + 4 < self.bytecode.len() &&
               self.bytecode[i+1] == 0x23 &&
               self.bytecode[i+2] == 0xb8 {
                
                // Check if this is in an owner-only function
                let has_owner_check = self.has_owner_modifier(i.saturating_sub(30));
                
                if has_owner_check {
                    // Check if it has additional validation
                    let has_amount_validation = self.bytecode[i..std::cmp::min(i+50, self.bytecode.len())]
                        .windows(2)
                        .any(|w| w[0] == 0x10 || w[0] == 0x11); // LT or GT
                    
                    if !has_amount_validation {
                        vulnerabilities.push(EmergencyFunctionAbuseVulnerability::EmergencyBypassesSecurity {
                            description: "Rescue function can transfer tokens without amount validation".to_string(),
                            location: i,
                            function_selector: "0x23b872dd".to_string(),
                            confidence: 0.75,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_emergency_function_pattern(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 80, self.bytecode.len());
        let section = &self.bytecode[location..end];
        
        // Emergency functions typically:
        // 1. Have external calls or transfers
        // 2. Access storage (withdrawal amounts)
        // 3. Are admin-protected
        
        let has_external_call = section.iter().any(|&b| b == 0xf1 || b == 0xf4);
        let has_storage_access = section.iter().any(|&b| b == 0x54 || b == 0x55);
        
        has_external_call && has_storage_access
    }
    
    fn has_owner_modifier(&self, location: usize) -> bool {
        // Look for owner check pattern: msg.sender == owner
        let start = location.saturating_sub(30);
        let end = std::cmp::min(location + 30, self.bytecode.len());
        
        self.bytecode[start..end]
            .windows(5)
            .any(|w| {
                w[0] == 0x33 && // CALLER
                w[2] == 0x54 && // SLOAD (owner)
                w[3] == 0x14    // EQ
            })
    }
    
    fn has_pause_check(&self, location: usize) -> bool {
        let start = location.saturating_sub(30);
        let end = std::cmp::min(location + 30, self.bytecode.len());
        
        self.bytecode[start..end]
            .windows(4)
            .any(|w| {
                w[0] == 0x54 && // SLOAD
                w[1] == 0x15 && // ISZERO
                w[2] == 0x15    // ISZERO (double negative for paused check)
            })
    }
    
    fn has_emergency_condition_check(&self, location: usize) -> bool {
        let start = location.saturating_sub(40);
        let end = std::cmp::min(location + 40, self.bytecode.len());
        
        // Look for emergency state variable check
        // Pattern: SLOAD, comparison, JUMPI
        self.bytecode[start..end]
            .windows(4)
            .filter(|w| {
                w[0] == 0x54 && // SLOAD
                (w[1] == 0x15 || w[1] == 0x14) && // ISZERO or EQ
                w[2] == 0x57 // JUMPI
            })
            .count() > 1 // More than just owner check
    }
    
    fn bypasses_normal_checks(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 80, self.bytecode.len());
        let section = &self.bytecode[location..end];
        
        // Check if function has transfers but minimal validation
        let has_transfer = section.iter().any(|&b| b == 0xf1);
        let validation_count = section.windows(2)
            .filter(|w| w[0] == 0x10 || w[0] == 0x11 || w[0] == 0x14)
            .count();
        
        has_transfer && validation_count < 2
    }
    
    fn find_critical_functions(&self) -> Vec<usize> {
        let mut locations = Vec::new();
        
        // Find functions that handle transfers or state changes
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let has_critical_ops = self.bytecode[i..std::cmp::min(i+50, self.bytecode.len())]
                    .iter()
                    .any(|&b| b == 0xf1 || b == 0x55); // CALL or SSTORE
                
                if has_critical_ops {
                    locations.push(i);
                }
            }
        }
        
        locations
    }
    
    fn checks_paused_modifier(&self, location: usize) -> bool {
        // Look for whenNotPaused modifier pattern
        let end = std::cmp::min(location + 40, self.bytecode.len());
        
        self.bytecode[location..end]
            .windows(4)
            .any(|w| {
                w[0] == 0x54 && // SLOAD (paused variable)
                w[1] == 0x15 && // ISZERO
                w[2] == 0x57    // JUMPI (revert if paused)
            })
    }
    
    fn is_in_admin_function(&self, location: usize) -> bool {
        // Look backwards for owner check
        let start = location.saturating_sub(50);
        
        self.bytecode[start..location]
            .windows(5)
            .any(|w| {
                w[0] == 0x33 && // CALLER
                w[2] == 0x54 && // SLOAD
                w[3] == 0x14    // EQ
            })
    }
    
    fn find_function_selector(&self, selector: u32) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(5) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let found = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2],
                    self.bytecode[i+3], self.bytecode[i+4],
                ]);
                if found == selector {
                    return Some(i);
                }
            }
        }
        None
    }
}
