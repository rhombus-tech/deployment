// Public Key Recovery Manipulation Detector
// Detects ecrecover edge cases and signature forgery vulnerabilities

use crate::bytecode::security::{SecuritySeverity, SecurityWarning};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicKeyRecoveryManipulationVulnerability {
    pub location: usize,
    pub vulnerability_type: PKRecoveryType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PKRecoveryType {
    EcrecoverEdgeCases,              // Unhandled ecrecover edge cases
    ZeroAddressAcceptance,           // Accept zero address from ecrecover
    InvalidSignatureHandling,        // Improper handling of invalid signatures
    VParameterManipulation,          // V parameter manipulation (27/28 vs 0/1)
    PrecompiledCallFailure,          // Unchecked ecrecover precompile failure
    CompactSignatureVulnerability,   // Compact signature format issues
}

pub struct PublicKeyRecoveryManipulationDetector {
    bytecode: Vec<u8>,
}

impl PublicKeyRecoveryManipulationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<PublicKeyRecoveryManipulationVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_ecrecover_edge_cases() {
            vulnerabilities.push(PublicKeyRecoveryManipulationVulnerability {
                location: loc,
                vulnerability_type: PKRecoveryType::EcrecoverEdgeCases,
                severity: SecuritySeverity::Critical,
                description: "ECRECOVER edge cases not handled. Invalid input parameters can return \
                             unexpected results enabling authentication bypass.".to_string(),
                confidence: 0.92,
            });
        }

        if let Some(loc) = self.detect_zero_address_acceptance() {
            vulnerabilities.push(PublicKeyRecoveryManipulationVulnerability {
                location: loc,
                vulnerability_type: PKRecoveryType::ZeroAddressAcceptance,
                severity: SecuritySeverity::Critical,
                description: "Zero address from ECRECOVER accepted as valid. Malformed signatures \
                             return 0x0 which passes authorization checks.".to_string(),
                confidence: 0.94,
            });
        }

        if let Some(loc) = self.detect_invalid_signature_handling() {
            vulnerabilities.push(PublicKeyRecoveryManipulationVulnerability {
                location: loc,
                vulnerability_type: PKRecoveryType::InvalidSignatureHandling,
                severity: SecuritySeverity::High,
                description: "Invalid signature error handling insufficient. Failed recovery treated \
                             as successful authentication attempt.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_v_parameter_manipulation() {
            vulnerabilities.push(PublicKeyRecoveryManipulationVulnerability {
                location: loc,
                vulnerability_type: PKRecoveryType::VParameterManipulation,
                severity: SecuritySeverity::High,
                description: "V parameter not normalized (27/28 vs 0/1). Signature malleability \
                             through V value manipulation enables replay attacks.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_precompiled_call_failure() {
            vulnerabilities.push(PublicKeyRecoveryManipulationVulnerability {
                location: loc,
                vulnerability_type: PKRecoveryType::PrecompiledCallFailure,
                severity: SecuritySeverity::Critical,
                description: "ECRECOVER precompile failure not checked. Out of gas or invalid \
                             parameters cause silent failure bypassing authentication.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_compact_signature_vulnerability() {
            vulnerabilities.push(PublicKeyRecoveryManipulationVulnerability {
                location: loc,
                vulnerability_type: PKRecoveryType::CompactSignatureVulnerability,
                severity: SecuritySeverity::High,
                description: "Compact signature parsing vulnerable. Compressed signature format \
                             allows parameter manipulation or confusion attacks.".to_string(),
                confidence: 0.85,
            });
        }

        vulnerabilities
    }

    fn detect_ecrecover_edge_cases(&self) -> Option<usize> {
        // Pattern: ECRECOVER without parameter validation
        // No checks on r, s, v values before recovery attempt
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x01 {  // ECRECOVER
                let mut has_parameter_validation = false;
                
                // Check for parameter validation (r, s in valid range, v = 27 or 28)
                for j in (i.saturating_sub(25))..i {
                    // R and S must be non-zero and < curve order
                    if self.bytecode[j] == 0x15 {  // ISZERO (check non-zero)
                        has_parameter_validation = true;
                    }
                    
                    // V parameter validation (must be 27 or 28)
                    if self.bytecode[j] == 0x60 && j+1 < self.bytecode.len() {
                        if self.bytecode[j+1] == 27 || self.bytecode[j+1] == 28 {
                            for k in j+2..(j+7).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x14 {  // EQ (validate V)
                                    has_parameter_validation = true;
                                }
                            }
                        }
                    }
                }
                
                if !has_parameter_validation {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_zero_address_acceptance(&self) -> Option<usize> {
        // Pattern: ECRECOVER result used without zero address check
        // Returned address compared/used without ISZERO check
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x01 {  // ECRECOVER
                let mut result_used = false;
                let mut checks_zero = false;
                
                // Check if result is used
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 {  // EQ (compare address)
                        result_used = true;
                    }
                    
                    // Check for zero address validation
                    if self.bytecode[j] == 0x15 {  // ISZERO (check if zero)
                        checks_zero = true;
                    }
                }
                
                if result_used && !checks_zero {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_invalid_signature_handling(&self) -> Option<usize> {
        // Pattern: ECRECOVER without checking return success
        // Precompile can fail but failure not detected
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x01 {  // ECRECOVER
                let mut checks_success = false;
                
                // ECRECOVER returns 0 on failure
                // Should check result is not zero before using
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Check if validating result is non-zero
                    if self.bytecode[j] == 0x15 {  // ISZERO
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 {  // ISZERO (double negative = check non-zero)
                                checks_success = true;
                            }
                        }
                    }
                }
                
                if !checks_success {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_v_parameter_manipulation(&self) -> Option<usize> {
        // Pattern: V parameter used without normalization
        // Accept both 0/1 and 27/28 without conversion
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x01 {  // ECRECOVER
                let mut has_v_normalization = false;
                
                // Check for V normalization (convert 0/1 to 27/28 or validate)
                for j in (i.saturating_sub(25))..i {
                    // V parameter handling
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD (V value)
                        for k in j+1..(j+20).min(self.bytecode.len()) {
                            // Normalization: add 27 if needed
                            if self.bytecode[k] == 0x60 && k+1 < self.bytecode.len() {
                                if self.bytecode[k+1] == 27 {  // PUSH1 27
                                    for m in k+2..(k+7).min(self.bytecode.len()) {
                                        if self.bytecode[m] == 0x01 {  // ADD (normalize)
                                            has_v_normalization = true;
                                        }
                                    }
                                }
                            }
                            
                            // Validation: check V is 27 or 28 only
                            if self.bytecode[k] == 0x14 {  // EQ (validate specific value)
                                has_v_normalization = true;
                            }
                        }
                    }
                }
                
                if !has_v_normalization {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_precompiled_call_failure(&self) -> Option<usize> {
        // Pattern: STATICCALL or CALL to ecrecover precompile without success check
        // 0x01 address call without checking return value
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Check for call to address 0x01 (ecrecover precompile)
            if self.bytecode[i] == 0x60 && i+1 < self.bytecode.len() {
                if self.bytecode[i+1] == 0x01 {  // PUSH1 1 (ecrecover address)
                    let mut has_call = false;
                    let mut checks_success = false;
                    
                    for j in i+2..(i+25).min(self.bytecode.len()) {
                        // Call to precompile
                        if self.bytecode[j] == 0xFA || self.bytecode[j] == 0xF1 {  // STATICCALL or CALL
                            has_call = true;
                        }
                        
                        // Check return value (1 = success, 0 = failure)
                        if self.bytecode[j] == 0x15 {  // ISZERO (check if failed)
                            checks_success = true;
                        }
                    }
                    
                    if has_call && !checks_success {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_compact_signature_vulnerability(&self) -> Option<usize> {
        // Pattern: Compact signature unpacking without validation
        // Extract r, s, v from single 65-byte value without bounds check
        
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (signature data)
                let mut unpacks_compact = false;
                let mut validates_components = false;
                
                // Check for bit manipulation (unpacking)
                for j in i+1..(i+30).min(self.bytecode.len()) {
                    // Unpacking operations (SHR, AND for extracting components)
                    if self.bytecode[j] == 0x1C || self.bytecode[j] == 0x16 {  // SHR or AND
                        unpacks_compact = true;
                    }
                    
                    // Validation of unpacked components
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT (bounds check)
                        validates_components = true;
                    }
                }
                
                if unpacks_compact && !validates_components {
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
                kind: crate::bytecode::security::SecurityWarningKind::Other(
                    format!("PublicKeyRecoveryManipulation{:?}", v.vulnerability_type)
                ),
                severity: v.severity,
                pc: v.location as u64,
                description: format!(
                    "Public Key Recovery Manipulation {:?}: {}",
                    v.vulnerability_type, v.description
                ),
                operations: Vec::new(),
                remediation: "Validate ecrecover parameters (r, s, v), check for zero address return, \
                             normalize V parameter to 27/28, verify precompile call success, validate \
                             compact signature component bounds, and handle all edge cases".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_address_acceptance() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x01, // ECRECOVER
            0x60, 0x00, // PUSH1 0
            0x14, // EQ (compare without zero check)
        ];
        
        let detector = PublicKeyRecoveryManipulationDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, PKRecoveryType::ZeroAddressAcceptance)));
    }

    #[test]
    fn test_ecrecover_edge_cases() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x01, // ECRECOVER (without parameter validation)
        ];
        
        let detector = PublicKeyRecoveryManipulationDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, PKRecoveryType::EcrecoverEdgeCases)));
    }
}
