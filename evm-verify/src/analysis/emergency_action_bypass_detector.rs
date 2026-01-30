// Emergency Action Bypass Detector
// Detects timelock circumvention and emergency mechanism abuse

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyActionBypassVulnerability {
    pub location: usize,
    pub vulnerability_type: EmergencyBypassType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmergencyBypassType {
    TimelockCircumvention,           // Bypass timelock delays
    GuardianRoleEscalation,          // Guardian exceeds intended authority
    EmergencyModeAbuse,              // Emergency mode activated without cause
    PauseGuardianCentralization,     // Single pause guardian controls system
    UpgradeDelayBypass,              // Bypass upgrade delay requirements
    CriticalFunctionExposure,        // Critical functions lack emergency protection
}

pub struct EmergencyActionBypassDetector {
    bytecode: Vec<u8>,
}

impl EmergencyActionBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EmergencyActionBypassVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_timelock_circumvention() {
            vulnerabilities.push(EmergencyActionBypassVulnerability {
                location: loc,
                vulnerability_type: EmergencyBypassType::TimelockCircumvention,
                severity: "Critical".to_string(),
                description: "Timelock can be bypassed through emergency function. Critical \
                             operations executable immediately without delay.".to_string(),
                confidence: 0.93,
            });
        }

        if let Some(loc) = self.detect_guardian_role_escalation() {
            vulnerabilities.push(EmergencyActionBypassVulnerability {
                location: loc,
                vulnerability_type: EmergencyBypassType::GuardianRoleEscalation,
                severity: "Critical".to_string(),
                description: "Guardian role has unrestricted powers beyond emergency response. \
                             Can execute arbitrary operations bypassing governance.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_emergency_mode_abuse() {
            vulnerabilities.push(EmergencyActionBypassVulnerability {
                location: loc,
                vulnerability_type: EmergencyBypassType::EmergencyModeAbuse,
                severity: "High".to_string(),
                description: "Emergency mode activation lacks validation. Can be triggered \
                             without legitimate cause to bypass normal controls.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_pause_guardian_centralization() {
            vulnerabilities.push(EmergencyActionBypassVulnerability {
                location: loc,
                vulnerability_type: EmergencyBypassType::PauseGuardianCentralization,
                severity: "High".to_string(),
                description: "Single pause guardian can halt entire system. No multisig or \
                             distributed control for critical pause functionality.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_upgrade_delay_bypass() {
            vulnerabilities.push(EmergencyActionBypassVulnerability {
                location: loc,
                vulnerability_type: EmergencyBypassType::UpgradeDelayBypass,
                severity: "Critical".to_string(),
                description: "Upgrade can bypass mandatory delay through emergency path. \
                             Malicious implementation deployable immediately.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_critical_function_exposure() {
            vulnerabilities.push(EmergencyActionBypassVulnerability {
                location: loc,
                vulnerability_type: EmergencyBypassType::CriticalFunctionExposure,
                severity: "High".to_string(),
                description: "Critical functions lack emergency pause protection. Operations \
                             continue during emergencies enabling further exploitation.".to_string(),
                confidence: 0.84,
            });
        }

        vulnerabilities
    }

    fn detect_timelock_circumvention(&self) -> Option<usize> {
        // Pattern: Function execution with emergency bypass of timelock
        // CALL to critical function without timestamp delay check
        
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0xF1 {  // CALL (critical operation)
                let mut has_timelock = false;
                let mut has_emergency_bypass = false;
                
                // Check for timelock verification
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 {  // LT/GT
                                has_timelock = true;
                            }
                        }
                    }
                }
                
                // Check for emergency bypass (OR condition skipping timelock)
                for j in (i.saturating_sub(30))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (emergency mode)
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x17 {  // OR (bypass timelock)
                                has_emergency_bypass = true;
                            }
                        }
                    }
                }
                
                if has_timelock && has_emergency_bypass {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_guardian_role_escalation(&self) -> Option<usize> {
        // Pattern: Guardian role with broad permissions
        // Guardian check allows execution of arbitrary functions
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x33 {  // CALLER
                let mut is_guardian_check = false;
                let mut has_function_restriction = false;
                
                // Check for guardian authorization
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 {  // SLOAD (guardian address)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (check guardian)
                                is_guardian_check = true;
                            }
                        }
                    }
                }
                
                // Check for function-specific restrictions
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD (function selector)
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (validate function)
                                has_function_restriction = true;
                            }
                        }
                    }
                }
                
                if is_guardian_check && !has_function_restriction {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_emergency_mode_abuse(&self) -> Option<usize> {
        // Pattern: Emergency mode activation without validation
        // Emergency flag set without checking conditions
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 {  // SSTORE (set emergency mode)
                let mut is_emergency_activation = false;
                let mut validates_conditions = false;
                
                // Check if emergency mode flag (boolean storage)
                for j in (i.saturating_sub(10))..i {
                    if self.bytecode[j] == 0x60 && j+1 < self.bytecode.len() {  // PUSH1
                        if self.bytecode[j+1] == 0x01 {  // true value
                            is_emergency_activation = true;
                        }
                    }
                }
                
                // Check for condition validation (oracle check, incident verification)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0xFA {  // STATICCALL (external validation)
                        validates_conditions = true;
                    }
                    if self.bytecode[j] == 0x54 {  // SLOAD (condition check)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 {  // LT/GT
                                validates_conditions = true;
                            }
                        }
                    }
                }
                
                if is_emergency_activation && !validates_conditions {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_pause_guardian_centralization(&self) -> Option<usize> {
        // Pattern: Pause function with single guardian authorization
        // No multisig or distributed control
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 {  // SSTORE (set paused state)
                let mut is_pause = false;
                let mut has_multisig = false;
                
                // Check if pause operation
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x60 && j+1 < self.bytecode.len() {
                        if self.bytecode[j+1] == 0x01 {  // true (paused)
                            is_pause = true;
                        }
                    }
                }
                
                // Check for multisig (multiple signature verifications)
                let mut sig_check_count = 0;
                for j in (i.saturating_sub(30))..i {
                    if self.bytecode[j] == 0x01 {  // ECRECOVER (signature verification)
                        sig_check_count += 1;
                    }
                }
                
                has_multisig = sig_check_count >= 2;
                
                if is_pause && !has_multisig {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_upgrade_delay_bypass(&self) -> Option<usize> {
        // Pattern: Upgrade execution with emergency bypass
        // Implementation change without timelock delay
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (set new implementation)
                let mut is_upgrade = false;
                let mut has_delay = false;
                let mut has_emergency_path = false;
                
                // Check if upgrade (storing new address)
                for j in (i.saturating_sub(20))..i {
                    // Address typically loaded with CALLDATALOAD or from storage
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD (new implementation)
                        is_upgrade = true;
                    }
                }
                
                // Check for delay enforcement
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        has_delay = true;
                    }
                }
                
                // Check for emergency bypass path
                for j in (i.saturating_sub(30))..i {
                    if self.bytecode[j] == 0x17 {  // OR (alternative path)
                        has_emergency_path = true;
                    }
                }
                
                if is_upgrade && has_delay && has_emergency_path {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_critical_function_exposure(&self) -> Option<usize> {
        // Pattern: Critical function without pause check
        // Transfer/withdrawal function not respecting pause state
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xF1 {  // CALL (transfer/withdrawal)
                let mut is_critical = false;
                let mut checks_pause = false;
                
                // Check if critical operation (value transfer)
                for j in (i.saturating_sub(20))..i {
                    // Check for value being transferred
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD (amount)
                        is_critical = true;
                    }
                }
                
                // Check for pause state verification
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x54 {  // SLOAD (paused flag)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 {  // ISZERO (check not paused)
                                checks_pause = true;
                            }
                        }
                    }
                }
                
                if is_critical && !checks_pause {
                    return Some(i);
                }
            }
        }
        None
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timelock_circumvention() {
        let bytecode = vec![
            0x42, // TIMESTAMP
            0x60, 0x00, // PUSH1 0
            0x10, // LT (timelock check)
            0x60, 0x01, // PUSH1 1
            0x17, // OR (emergency bypass)
            0xF1, // CALL (execute immediately)
        ];
        
        let detector = EmergencyActionBypassDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, EmergencyBypassType::TimelockCircumvention)));
    }

    #[test]
    fn test_pause_guardian_centralization() {
        let bytecode = vec![
            0x60, 0x01, // PUSH1 1 (paused = true)
            0x55, // SSTORE (single guardian can pause)
        ];
        
        let detector = EmergencyActionBypassDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, EmergencyBypassType::PauseGuardianCentralization)));
    }
}
