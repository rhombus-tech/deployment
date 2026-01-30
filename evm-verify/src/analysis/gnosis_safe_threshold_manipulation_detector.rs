use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnosisSafeThresholdVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct GnosisSafeThresholdManipulationDetector {
    bytecode: Vec<u8>,
}

impl GnosisSafeThresholdManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<GnosisSafeThresholdVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Gnosis Safe uses M-of-N signature threshold
        // Detect threshold manipulation
        if let Some(location) = self.has_threshold_manipulation() {
            vulnerabilities.push(GnosisSafeThresholdVulnerability {
                vulnerability_type: "Gnosis Safe Threshold Manipulation".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Signature threshold can be changed without sufficient current signatures. Malicious owners can lower threshold to gain solo control. Require threshold-1 signatures to change threshold.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect owner removal bypass
        if let Some(location) = self.has_owner_removal_bypass() {
            vulnerabilities.push(GnosisSafeThresholdVulnerability {
                vulnerability_type: "Gnosis Safe Owner Removal Bypass".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Owner removal without threshold validation. Removing owners while maintaining threshold allows remaining owners to gain excessive control. Validate threshold <= ownerCount after removal.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect signature replay across threshold changes
        if let Some(location) = self.has_signature_replay_risk() {
            vulnerabilities.push(GnosisSafeThresholdVulnerability {
                vulnerability_type: "Gnosis Safe Signature Replay".to_string(),
                location,
                severity: "High".to_string(),
                description: "Signatures not invalidated after threshold/owner changes. Old signature sets can be replayed after governance modifications. Include threshold/owner hash in signature domain.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_threshold_manipulation(&self) -> Option<usize> {
        // Pattern: Threshold storage update without signature count validation
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x55 { // SSTORE (setting threshold)
                // Check if sufficient signatures validated
                let mut has_signature_validation = false;
                
                for j in i.saturating_sub(40)..i {
                    // Look for signature count check
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 { // LT/GT comparison
                        // Check if comparing signature count with threshold
                        for k in j.saturating_sub(10)..j {
                            // Counter pattern (signature count)
                            if self.bytecode[k] == 0x01 { // ADD (incrementing sig count)
                                has_signature_validation = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_signature_validation {
                    // Verify this is threshold-related (small value)
                    for j in i.saturating_sub(10)..i {
                        if self.bytecode[j] == 0x60 { // PUSH1 (threshold value)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_owner_removal_bypass(&self) -> Option<usize> {
        // Pattern: Owner removal without threshold consistency check
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for owner count decrement
            if self.bytecode[i] == 0x03 { // SUB (ownerCount - 1)
                // Check if threshold is validated against new owner count
                let mut has_threshold_validation = false;
                
                for j in i+1..i+30.min(self.bytecode.len()) {
                    // Look for threshold comparison with new owner count
                    if self.bytecode[j] == 0x10 { // LT (threshold <= ownerCount)
                        has_threshold_validation = true;
                        break;
                    }
                }
                
                if !has_threshold_validation {
                    // Verify this is owner management (SSTORE after SUB)
                    for j in i+1..i+20.min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // SSTORE (updating owner count)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_signature_replay_risk(&self) -> Option<usize> {
        // Pattern: Signature verification without domain separator update
        for i in 0..self.bytecode.len().saturating_sub(45) {
            // Look for ECRECOVER (signature verification)
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xfa { // CALL/STATICCALL
                // Check if this is ecrecover (address 0x01)
                let mut is_ecrecover = false;
                for j in i.saturating_sub(10)..i {
                    if self.bytecode[j] == 0x60 { // PUSH1
                        if j + 1 < self.bytecode.len() && self.bytecode[j + 1] == 0x01 {
                            is_ecrecover = true;
                        }
                    }
                }
                
                if is_ecrecover {
                    // Check if domain separator includes threshold/owner state
                    let mut has_state_in_domain = false;
                    
                    for j in i.saturating_sub(40)..i {
                        // Look for threshold/owner count in hash computation
                        if self.bytecode[j] == 0x20 { // SHA3 (domain separator)
                            // Check if SLOAD used in hash (includes state)
                            for k in j.saturating_sub(20)..j {
                                if self.bytecode[k] == 0x54 { // SLOAD (threshold/owners)
                                    has_state_in_domain = true;
                                    break;
                                }
                            }
                        }
                    }
                    
                    if !has_state_in_domain {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
