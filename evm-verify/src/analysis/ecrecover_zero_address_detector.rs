use serde::{Deserialize, Serialize};

/// Ecrecover Zero Address Vulnerability Detector
/// 
/// Detects when ecrecover results are not checked for address(0).
/// CRITICAL: ecrecover returns address(0) on invalid signatures.
/// 
/// Real-world impact: Ronin Bridge hack ($625M)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EcrecoverZeroAddressVulnerability {
    /// Critical: ecrecover result used without zero check
    UncheckedEcrecoverResult {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// High: ecrecover in signature validation without zero check
    SignatureValidationNoZeroCheck {
        description: String,
        location: usize,
    },
    /// High: Zero address authorized in access control
    ZeroAddressAuthorized {
        description: String,
        location: usize,
    },
    /// Medium: ecrecover result stored without validation
    StoredWithoutValidation {
        description: String,
        location: usize,
    },
}

pub struct EcrecoverZeroAddressDetector {
    bytecode: Vec<u8>,
}

impl EcrecoverZeroAddressDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<EcrecoverZeroAddressVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Find all ecrecover calls
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.is_ecrecover_call(i) {
                // Pattern 1: Check if result is validated for zero
                if !self.has_zero_check_after(i, i + 40) {
                    let in_validator = self.is_in_validator_context(i);
                    let confidence = if in_validator { 0.95 } else { 0.85 };
                    
                    vulnerabilities.push(EcrecoverZeroAddressVulnerability::UncheckedEcrecoverResult {
                        description: format!(
                            "ecrecover at position {} returns address(0) on invalid signatures but result not checked. \
                            This can bypass signature validation if address(0) is in authorized set.",
                            i
                        ),
                        location: i,
                        confidence,
                    });
                }
                
                // Pattern 2: ecrecover result used in signature validation
                if self.used_in_signature_validation(i, i + 60) {
                    if !self.has_zero_check_after(i, i + 60) {
                        vulnerabilities.push(EcrecoverZeroAddressVulnerability::SignatureValidationNoZeroCheck {
                            description: "ecrecover used in signature validation without checking for address(0)".to_string(),
                            location: i,
                        });
                    }
                }
                
                // Pattern 3: ecrecover result stored without validation
                if self.result_stored_to_state(i, i + 50) {
                    if !self.has_zero_check_before_storage(i, i + 50) {
                        vulnerabilities.push(EcrecoverZeroAddressVulnerability::StoredWithoutValidation {
                            description: "ecrecover result stored to state without zero address check".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 4: Check if address(0) is authorized
        if self.zero_address_in_authorized_set() {
            vulnerabilities.push(EcrecoverZeroAddressVulnerability::ZeroAddressAuthorized {
                description: "address(0) appears to be in authorized validators/signers set".to_string(),
                location: 0,
            });
        }
        
        vulnerabilities
    }
    
    fn is_ecrecover_call(&self, location: usize) -> bool {
        if location + 10 > self.bytecode.len() {
            return false;
        }
        
        // Pattern: PUSH1 0x01 (ecrecover precompile) followed by STATICCALL or CALL
        // Look for: 0x60 0x01 ... 0xFA (STATICCALL) or 0xF1 (CALL)
        
        for offset in 0..10 {
            if location + offset + 2 < self.bytecode.len() {
                if self.bytecode[location + offset] == 0x60 && // PUSH1
                   self.bytecode[location + offset + 1] == 0x01 { // ecrecover address
                    // Check for CALL/STATICCALL nearby
                    for j in (location + offset + 2)..(location + offset + 15).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xFA || self.bytecode[j] == 0xF1 {
                            return true;
                        }
                    }
                }
            }
        }
        
        false
    }
    
    fn has_zero_check_after(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Look for patterns that check for zero address:
        // 1. PUSH 0, EQ, ISZERO, REVERT
        // 2. ISZERO, REVERT (checking result directly)
        // 3. DUP, PUSH 0, EQ, condition jump
        
        for i in start..range_end.saturating_sub(5) {
            // Pattern: PUSH1 0x00, EQ
            if self.bytecode[i] == 0x60 && 
               self.bytecode[i + 1] == 0x00 && 
               i + 2 < range_end &&
               self.bytecode[i + 2] == 0x14 { // EQ
                // Check if followed by ISZERO and REVERT/JUMPI
                if i + 3 < range_end && self.bytecode[i + 3] == 0x15 { // ISZERO
                    if i + 4 < range_end && 
                       (self.bytecode[i + 4] == 0xFD || // REVERT
                        self.bytecode[i + 4] == 0x57) { // JUMPI
                        return true;
                    }
                }
                return true;
            }
            
            // Pattern: ISZERO (checking if address is non-zero)
            if self.bytecode[i] == 0x15 && i + 1 < range_end {
                // Followed by conditional or revert
                if self.bytecode[i + 1] == 0xFD || self.bytecode[i + 1] == 0x57 {
                    return true;
                }
            }
        }
        
        false
    }
    
    fn is_in_validator_context(&self, location: usize) -> bool {
        // Check if ecrecover is used in a validator/authorization context
        // Look for: isValidator, hasRole, authorized, etc. function signatures nearby
        
        let start = location.saturating_sub(100);
        let end = (location + 100).min(self.bytecode.len());
        
        // Common validator function selectors
        let validator_patterns = [
            [0x91, 0xd1, 0x48, 0x54], // hasRole(bytes32,address)
            [0x21, 0x7f, 0xe6, 0xc6], // isValidator(address)
            [0xfe, 0x9d, 0x93, 0x03], // authorized(address)
        ];
        
        for pattern in &validator_patterns {
            for i in start..end.saturating_sub(4) {
                if &self.bytecode[i..i + 4] == pattern {
                    return true;
                }
            }
        }
        
        false
    }
    
    fn used_in_signature_validation(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // After ecrecover, look for comparison or role check patterns
        // Signature validation typically: ecrecover -> compare/check -> revert if invalid
        
        for i in start..range_end.saturating_sub(3) {
            // Look for EQ or comparison operations
            if self.bytecode[i] == 0x14 || // EQ
               self.bytecode[i] == 0x10 || // LT
               self.bytecode[i] == 0x11 {  // GT
                return true;
            }
        }
        
        false
    }
    
    fn result_stored_to_state(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Check if ecrecover result is followed by SSTORE
        for i in start..range_end {
            if self.bytecode[i] == 0x55 { // SSTORE
                return true;
            }
        }
        
        false
    }
    
    fn has_zero_check_before_storage(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Check if there's validation before SSTORE
        let mut found_check = false;
        
        for i in start..range_end {
            // Zero check
            if self.bytecode[i] == 0x15 || // ISZERO
               (self.bytecode[i] == 0x60 && i + 1 < range_end && self.bytecode[i + 1] == 0x00) {
                found_check = true;
            }
            
            // If we find SSTORE, check if validation happened before
            if self.bytecode[i] == 0x55 {
                return found_check;
            }
        }
        
        false
    }
    
    fn zero_address_in_authorized_set(&self) -> bool {
        // Look for patterns where address(0) might be added to authorized set
        // This is heuristic-based and looks for suspicious patterns
        
        // Pattern: PUSH 0x00 followed by SSTORE to authorization storage
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x60 && self.bytecode[i + 1] == 0x00 {
                // Check if this is stored to a mapping-like structure
                for j in i + 2..(i + 10).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 { // SSTORE
                        // Check if TRUE value is stored (authorization flag)
                        for k in i..j {
                            if self.bytecode[k] == 0x60 && 
                               k + 1 < self.bytecode.len() && 
                               self.bytecode[k + 1] == 0x01 {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        
        false
    }
}
