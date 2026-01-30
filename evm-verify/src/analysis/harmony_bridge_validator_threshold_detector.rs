use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarmonyBridgeValidatorThresholdVulnerability {
    pub location: usize,
    pub threshold_type: ValidatorThresholdType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidatorThresholdType {
    InsufficientThreshold,           // Threshold too low for security
    StaticValidatorSet,              // Validator set cannot change
    NoThresholdEnforcement,          // Threshold not enforced
    CompromisedValidatorBypass,      // Single validator can bypass
    ThresholdManipulation,           // Threshold can be lowered
    ValidatorKeyCompromise,          // Key management weakness
}

pub struct HarmonyBridgeValidatorThresholdDetector {
    bytecode: Vec<u8>,
}

impl HarmonyBridgeValidatorThresholdDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<HarmonyBridgeValidatorThresholdVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_insufficient_threshold() {
            vulnerabilities.push(HarmonyBridgeValidatorThresholdVulnerability {
                location: loc,
                threshold_type: ValidatorThresholdType::InsufficientThreshold,
                severity: "Critical".to_string(),
                description: "Bridge validator threshold insufficient for security. Harmony $100M exploit: \
                             2-of-5 multisig compromised. Threshold MUST be >2/3 of validators for BFT \
                             security, preferably 5-of-9 minimum.".to_string(),
                confidence: 0.94,
            });
        }

        if let Some(loc) = self.detect_static_validator_set() {
            vulnerabilities.push(HarmonyBridgeValidatorThresholdVulnerability {
                location: loc,
                threshold_type: ValidatorThresholdType::StaticValidatorSet,
                severity: "High".to_string(),
                description: "Validator set is static and cannot be rotated. If validators compromised, \
                             no mechanism exists to replace them without full redeployment.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_no_threshold_enforcement() {
            vulnerabilities.push(HarmonyBridgeValidatorThresholdVulnerability {
                location: loc,
                threshold_type: ValidatorThresholdType::NoThresholdEnforcement,
                severity: "Critical".to_string(),
                description: "Signature threshold not enforced on-chain. Allows fewer signatures than \
                             required threshold to authorize bridge operations.".to_string(),
                confidence: 0.92,
            });
        }

        if let Some(loc) = self.detect_compromised_validator_bypass() {
            vulnerabilities.push(HarmonyBridgeValidatorThresholdVulnerability {
                location: loc,
                threshold_type: ValidatorThresholdType::CompromisedValidatorBypass,
                severity: "Critical".to_string(),
                description: "Single validator can bypass threshold in edge cases. Emergency or admin \
                             functions allow threshold bypass with single signature.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_threshold_manipulation() {
            vulnerabilities.push(HarmonyBridgeValidatorThresholdVulnerability {
                location: loc,
                threshold_type: ValidatorThresholdType::ThresholdManipulation,
                severity: "Critical".to_string(),
                description: "Validator threshold can be lowered by compromised validators. No timelock \
                             or governance delay on threshold changes.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_validator_key_compromise() {
            vulnerabilities.push(HarmonyBridgeValidatorThresholdVulnerability {
                location: loc,
                threshold_type: ValidatorThresholdType::ValidatorKeyCompromise,
                severity: "High".to_string(),
                description: "Validator key management vulnerable. Keys stored insecurely or no key \
                             rotation mechanism enables compromise.".to_string(),
                confidence: 0.85,
            });
        }

        vulnerabilities
    }

    fn detect_insufficient_threshold(&self) -> Option<usize> {
        // Check threshold value in validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if matches!(self.bytecode[i], 0x60..=0x7f) { // PUSH (threshold constant)
                // Look for signature count comparison
                for j in i + 1..std::cmp::min(i + 25, self.bytecode.len()) {
                    if matches!(self.bytecode[j], 0x10 | 0x11) { // LT or GT
                        // Extract threshold value
                        let push_size = (self.bytecode[i] - 0x5f) as usize;
                        if i + push_size < self.bytecode.len() && push_size == 1 {
                            let threshold = self.bytecode[i + 1];
                            // Check for low thresholds (2, 3, etc.)
                            if threshold <= 3 {
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_static_validator_set(&self) -> Option<usize> {
        // Check for validator set update function
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // addValidator (0x4d238c8e), removeValidator (0x40a141ff)
                if selector == 0x4d238c8e || selector == 0x40a141ff {
                    return None; // Has validator management
                }
            }
        }
        
        // If no validator management found, check for signature verification
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x01 { // ECRECOVER would indicate sig verification
                return Some(i); // Static validator set with sig verification
            }
        }
        None
    }

    fn detect_no_threshold_enforcement(&self) -> Option<usize> {
        // Signature verification without threshold check
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x01 { // ECRECOVER
                // Check for counter/threshold comparison afterward
                let mut has_threshold_check = false;
                for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                    if matches!(self.bytecode[j], 0x10 | 0x11) { // LT or GT
                        has_threshold_check = true;
                        break;
                    }
                }
                if !has_threshold_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_compromised_validator_bypass(&self) -> Option<usize> {
        // Emergency function with single signature
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // Emergency functions
                if selector == 0xdb2e21bc || selector == 0xa433e58b { // emergencyWithdraw, emergencyPause
                    // Check for single signature vs threshold
                    let mut sig_count = 0;
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        if self.bytecode[j] == 0x01 { // ECRECOVER
                            sig_count += 1;
                        }
                    }
                    if sig_count == 1 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_threshold_manipulation(&self) -> Option<usize> {
        // setThreshold function without timelock
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // setThreshold (0x960bfe04), updateThreshold (0x8b0e9f3f)
                if selector == 0x960bfe04 || selector == 0x8b0e9f3f {
                    // Check for timelock (timestamp + delay)
                    let mut has_timelock = false;
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 { // TIMESTAMP
                            for k in j + 1..std::cmp::min(j + 10, self.bytecode.len()) {
                                if self.bytecode[k] == 0x01 { // ADD (delay)
                                    has_timelock = true;
                                    break;
                                }
                            }
                            if has_timelock {
                                break;
                            }
                        }
                    }
                    if !has_timelock {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_validator_key_compromise(&self) -> Option<usize> {
        // Validator address stored in contract without rotation
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for validator address storage
            if self.bytecode[i] == 0x73 && i + 20 < self.bytecode.len() { // PUSH20 (address)
                // Check if this is compared in validation
                for j in i + 21..std::cmp::min(i + 25, self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 { // EQ (checking validator)
                        // Check for key rotation mechanism
                        let has_rotation = self.bytecode.windows(4).any(|w| {
                            if w[0] == 0x63 {
                                let sel = u32::from_be_bytes([w[0], w[1], w[2], w[3]]);
                                sel == 0x4d238c8e || sel == 0x40a141ff // add/remove validator
                            } else {
                                false
                            }
                        });
                        if !has_rotation {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
