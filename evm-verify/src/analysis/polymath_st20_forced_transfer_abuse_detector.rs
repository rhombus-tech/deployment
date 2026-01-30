// Polymath ST-20 Forced Transfer Abuse Detector
// Detects abuse of forced transfer mechanisms in security tokens

use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolymathST20Vulnerability {
    pub location: usize,
    pub vulnerability_type: PolymathVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolymathVulnerabilityType {
    ForcedTransferAbuse,            // Abuse forced transfer authority
    IssuanceAuthorizationBypass,    // Bypass issuance authorization
    TransferManagerBypass,          // Bypass transfer manager checks
    ModulePermissionEscalation,     // Escalate module permissions
    CheckpointManipulation,         // Manipulate dividend checkpoints
    ControllerOverreach,            // Controller exceeds intended authority
}

pub struct PolymathST20Detector {
    bytecode: Vec<u8>,
}

impl PolymathST20Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<PolymathST20Vulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_forced_transfer_abuse() {
            vulnerabilities.push(PolymathST20Vulnerability {
                location: loc,
                vulnerability_type: PolymathVulnerabilityType::ForcedTransferAbuse,
                severity: SecuritySeverity::Critical,
                description: "Forced transfer lacks proper authorization checks. Controller can seize \
                             tokens from any holder without proper legal justification or oversight.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_issuance_bypass() {
            vulnerabilities.push(PolymathST20Vulnerability {
                location: loc,
                vulnerability_type: PolymathVulnerabilityType::IssuanceAuthorizationBypass,
                severity: SecuritySeverity::Critical,
                description: "Token issuance bypasses transfer manager validation. New tokens issued \
                             to non-compliant addresses violating regulatory requirements.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_transfer_manager_bypass() {
            vulnerabilities.push(PolymathST20Vulnerability {
                location: loc,
                vulnerability_type: PolymathVulnerabilityType::TransferManagerBypass,
                severity: SecuritySeverity::High,
                description: "Transfer bypasses transfer manager through alternative path. Compliance \
                             checks skipped on certain transfer types.".to_string(),
                confidence: 0.85,
            });
        }

        if let Some(loc) = self.detect_permission_escalation() {
            vulnerabilities.push(PolymathST20Vulnerability {
                location: loc,
                vulnerability_type: PolymathVulnerabilityType::ModulePermissionEscalation,
                severity: SecuritySeverity::High,
                description: "Module permission check vulnerable to escalation. Module can gain \
                             unintended privileges through permission delegation.".to_string(),
                confidence: 0.83,
            });
        }

        if let Some(loc) = self.detect_checkpoint_manipulation() {
            vulnerabilities.push(PolymathST20Vulnerability {
                location: loc,
                vulnerability_type: PolymathVulnerabilityType::CheckpointManipulation,
                severity: SecuritySeverity::Medium,
                description: "Checkpoint creation timing manipulable. Dividend snapshots can be timed \
                             to exclude legitimate holders or include ineligible ones.".to_string(),
                confidence: 0.78,
            });
        }

        if let Some(loc) = self.detect_controller_overreach() {
            vulnerabilities.push(PolymathST20Vulnerability {
                location: loc,
                vulnerability_type: PolymathVulnerabilityType::ControllerOverreach,
                severity: SecuritySeverity::Critical,
                description: "Controller authority lacks bounds. Controller operations not limited to \
                             legally justified scenarios, enabling arbitrary token manipulation.".to_string(),
                confidence: 0.87,
            });
        }

        vulnerabilities
    }

    fn detect_forced_transfer_abuse(&self) -> Option<usize> {
        // Pattern: Forced transfer without authorization validation
        // Transfer function with controller check but no reason/justification verification
        
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x33 {  // CALLER
                let mut has_controller_check = false;
                let mut has_justification_check = false;
                let mut has_transfer = false;
                
                for j in i+1..(i+30).min(self.bytecode.len()) {
                    // Controller authorization
                    if self.bytecode[j] == 0x14 {  // EQ (check controller)
                        has_controller_check = true;
                    }
                    
                    // Justification/reason validation (additional SLOAD for approval record)
                    if has_controller_check && self.bytecode[j] == 0x54 {  // SLOAD (justification)
                        has_justification_check = true;
                    }
                    
                    // Transfer execution (balance updates)
                    if self.bytecode[j] == 0x55 {  // SSTORE (balance change)
                        has_transfer = true;
                    }
                }
                
                // Controller can force transfer without justification
                if has_controller_check && has_transfer && !has_justification_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_issuance_bypass(&self) -> Option<usize> {
        // Pattern: Mint function without transfer manager validation
        // Token creation without compliance check
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 {  // SSTORE (mint - increase balance)
                let mut validates_compliance = false;
                let mut is_mint = false;
                
                // Check if this is minting (totalSupply increase)
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {  // SSTORE (totalSupply)
                        is_mint = true;
                    }
                }
                
                // Check for transfer manager validation
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0xFA {  // STATICCALL (transfer manager)
                        validates_compliance = true;
                    }
                }
                
                if is_mint && !validates_compliance {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_transfer_manager_bypass(&self) -> Option<usize> {
        // Pattern: Transfer path without transfer manager call
        // Balance update without verifyTransfer call
        
        for i in 0..self.bytecode.len().saturating_sub(35) {
            // Look for balance update (transfer)
            if self.bytecode[i] == 0x03 {  // SUB (reduce sender balance)
                let mut has_manager_check = false;
                let mut has_recipient_update = false;
                
                // Check for transfer manager verification
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0xFA {  // STATICCALL (verifyTransfer)
                        has_manager_check = true;
                    }
                }
                
                // Check if recipient balance updated (completing transfer)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x01 {  // ADD (increase recipient balance)
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x55 {  // SSTORE
                                has_recipient_update = true;
                            }
                        }
                    }
                }
                
                // Transfer without compliance check
                if has_recipient_update && !has_manager_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_permission_escalation(&self) -> Option<usize> {
        // Pattern: Permission check using delegated authority
        // Module permission without origin validation
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x54 {  // SLOAD (permission)
                let mut checks_origin = false;
                let mut grants_permission = false;
                
                // Check if permission granted based on this load
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x15 {  // ISZERO (has permission)
                        grants_permission = true;
                    }
                    
                    // Origin check: CALLER compared against original granter
                    if self.bytecode[j] == 0x33 {  // CALLER
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (verify origin)
                                checks_origin = true;
                            }
                        }
                    }
                }
                
                // Permission granted without origin validation
                if grants_permission && !checks_origin {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_checkpoint_manipulation(&self) -> Option<usize> {
        // Pattern: Checkpoint creation without delay/protection
        // Checkpoint created immediately allowing gaming
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 {  // SSTORE (create checkpoint)
                let mut has_delay = false;
                let mut has_notice_period = false;
                
                // Check for delay enforcement
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x01 {  // ADD (future time)
                                has_delay = true;
                            }
                        }
                    }
                    
                    // Notice period: compare against announced time
                    if self.bytecode[j] == 0x54 {  // SLOAD (announced time)
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (enough notice)
                                has_notice_period = true;
                            }
                        }
                    }
                }
                
                // Check if this looks like checkpoint (multiple SSTOREs)
                let mut sstore_count = 1;
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {
                        sstore_count += 1;
                    }
                }
                
                if sstore_count >= 2 && !has_delay && !has_notice_period {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_controller_overreach(&self) -> Option<usize> {
        // Pattern: Controller operations without scope limits
        // Controller can modify arbitrary state without constraints
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x33 {  // CALLER
                let mut is_controller = false;
                let mut has_scope_limit = false;
                let mut has_broad_access = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Controller check
                    if self.bytecode[j] == 0x14 {  // EQ (is controller)
                        is_controller = true;
                    }
                    
                    // Scope limiting: specific operation type check
                    if is_controller && self.bytecode[j] == 0x35 {  // CALLDATALOAD (operation type)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (validate operation type)
                                has_scope_limit = true;
                            }
                        }
                    }
                    
                    // Broad access: multiple SSTOREs possible
                    if is_controller && self.bytecode[j] == 0x55 {  // SSTORE
                        has_broad_access = true;
                    }
                }
                
                // Controller with broad access and no scope limits
                if is_controller && has_broad_access && !has_scope_limit {
                    return Some(i);
                }
            }
        }
        None
    }

    pub fn to_security_warnings(&self) -> Vec<SecurityWarning> {
        self.detect()
            .into_iter()
            .map(|v| SecurityWarning {
                kind: SecurityWarningKind::PolymathST20,
                severity: v.severity,
                description: format!(
                    "Polymath ST-20 {:?} at PC {}: {}",
                    v.vulnerability_type, v.location, v.description
                ),
                pc: v.location as u64,
                operations: Vec::new(),
                remediation: "Review protocol-specific security measures".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forced_transfer_abuse() {
        let bytecode = vec![
            0x33, // CALLER
            0x60, 0x00, // PUSH1 0
            0x14, // EQ (check controller)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (force transfer without justification)
        ];
        
        let detector = PolymathST20Detector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, PolymathVulnerabilityType::ForcedTransferAbuse)));
    }

    #[test]
    fn test_issuance_bypass() {
        let bytecode = vec![
            0x60, 0x64, // PUSH1 100 (amount)
            0x55, // SSTORE (mint to balance)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (update totalSupply - no compliance check)
        ];
        
        let detector = PolymathST20Detector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, PolymathVulnerabilityType::IssuanceAuthorizationBypass)));
    }
}
