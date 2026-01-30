// Signature Scheme Downgrade Detector
// Detects forcing of weaker signature schemes and cryptographic downgrades

use crate::bytecode::security::{SecuritySeverity, SecurityWarning};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureSchemeDowngradeVulnerability {
    pub location: usize,
    pub vulnerability_type: SignatureDowngradeType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureDowngradeType {
    WeakerSignatureForcing,          // Force use of weaker signature scheme
    AlgorithmNegotiationFlawed,      // Vulnerable signature selection logic
    DeprecatedCurveAcceptance,       // Accept deprecated elliptic curves
    ShortSignatureAcceptance,        // Accept signatures with insufficient length
    MalleabilityVulnerability,       // Signature malleability not prevented
    HashAlgorithmDowngrade,          // Force weaker hash in signature
}

pub struct SignatureSchemeDowngradeDetector {
    bytecode: Vec<u8>,
}

impl SignatureSchemeDowngradeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SignatureSchemeDowngradeVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_weaker_signature_forcing() {
            vulnerabilities.push(SignatureSchemeDowngradeVulnerability {
                location: loc,
                vulnerability_type: SignatureDowngradeType::WeakerSignatureForcing,
                severity: SecuritySeverity::Critical,
                description: "Multiple signature schemes accepted without strength validation. \
                             Attacker can force use of weaker scheme compromising security.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_algorithm_negotiation_flawed() {
            vulnerabilities.push(SignatureSchemeDowngradeVulnerability {
                location: loc,
                vulnerability_type: SignatureDowngradeType::AlgorithmNegotiationFlawed,
                severity: SecuritySeverity::High,
                description: "Signature algorithm selection controllable by attacker. Can choose \
                             weakest accepted algorithm for easier forgery attempts.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_deprecated_curve_acceptance() {
            vulnerabilities.push(SignatureSchemeDowngradeVulnerability {
                location: loc,
                vulnerability_type: SignatureDowngradeType::DeprecatedCurveAcceptance,
                severity: SecuritySeverity::Critical,
                description: "Deprecated elliptic curves accepted for signature verification. \
                             Known weak curves allow signature forgery or recovery attacks.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_short_signature_acceptance() {
            vulnerabilities.push(SignatureSchemeDowngradeVulnerability {
                location: loc,
                vulnerability_type: SignatureDowngradeType::ShortSignatureAcceptance,
                severity: SecuritySeverity::High,
                description: "Signature length validation missing or inadequate. Short signatures \
                             accepted reducing cryptographic strength and collision resistance.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_malleability_vulnerability() {
            vulnerabilities.push(SignatureSchemeDowngradeVulnerability {
                location: loc,
                vulnerability_type: SignatureDowngradeType::MalleabilityVulnerability,
                severity: SecuritySeverity::High,
                description: "Signature malleability not prevented. Alternative valid signatures \
                             can be created for same message enabling replay attacks.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_hash_algorithm_downgrade() {
            vulnerabilities.push(SignatureSchemeDowngradeVulnerability {
                location: loc,
                vulnerability_type: SignatureDowngradeType::HashAlgorithmDowngrade,
                severity: SecuritySeverity::Critical,
                description: "Hash algorithm in signature scheme negotiable. Attacker can force \
                             weaker hash like SHA1 instead of SHA256 enabling collisions.".to_string(),
                confidence: 0.90,
            });
        }

        vulnerabilities
    }

    fn detect_weaker_signature_forcing(&self) -> Option<usize> {
        // Pattern: Multiple signature verification paths without strength check
        // ECRECOVER with different parameter sets accepted equally
        
        let mut ecrecover_count = 0;
        let mut has_strength_validation = false;
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x01 {  // ECRECOVER
                ecrecover_count += 1;
                
                // Check for signature strength validation
                for j in (i.saturating_sub(20))..i {
                    // Curve parameter validation (specific values required)
                    if self.bytecode[j] == 0x60 || self.bytecode[j] == 0x61 {  // PUSH
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (verify curve params)
                                has_strength_validation = true;
                            }
                        }
                    }
                }
            }
        }
        
        // Multiple signature paths without validation
        if ecrecover_count >= 2 && !has_strength_validation {
            return Some(0);
        }
        
        None
    }

    fn detect_algorithm_negotiation_flawed(&self) -> Option<usize> {
        // Pattern: Algorithm selection from untrusted input
        // CALLDATALOAD determines which signature scheme to use
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (algorithm choice)
                let mut controls_verification = false;
                let mut has_whitelist = false;
                
                // Check if used to select verification path
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x57 {  // JUMPI (conditional branch)
                        controls_verification = true;
                    }
                }
                
                // Check for algorithm whitelist
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 {  // EQ (check against allowed list)
                        has_whitelist = true;
                    }
                }
                
                if controls_verification && !has_whitelist {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_deprecated_curve_acceptance(&self) -> Option<usize> {
        // Pattern: ECRECOVER without curve parameter validation
        // Accepts any curve without checking it's secure
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x01 {  // ECRECOVER
                let mut validates_curve = false;
                
                // Check for secp256k1 specific validation (only safe curve for Ethereum)
                for j in (i.saturating_sub(20))..i {
                    // Curve order validation or parameter check
                    if self.bytecode[j] == 0x60 || self.bytecode[j] == 0x61 {  // PUSH (curve param)
                        for k in j+1..(j+15).min(self.bytecode.len()) {
                            // Verify against known good curve parameters
                            if self.bytecode[k] == 0x14 {  // EQ (validate)
                                validates_curve = true;
                            }
                        }
                    }
                }
                
                if !validates_curve {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_short_signature_acceptance(&self) -> Option<usize> {
        // Pattern: Signature length not validated
        // ECRECOVER input without length check
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x01 {  // ECRECOVER
                let mut has_length_check = false;
                
                // Check for signature length validation (should be 65 bytes)
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD (signature data)
                        for k in j+1..(j+20).min(self.bytecode.len()) {
                            // Length comparison
                            if self.bytecode[k] == 0x60 && k+1 < self.bytecode.len() {
                                if self.bytecode[k+1] == 65 {  // PUSH1 65
                                    for m in k+2..(k+7).min(self.bytecode.len()) {
                                        if self.bytecode[m] == 0x14 {  // EQ (validate length)
                                            has_length_check = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                if !has_length_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_malleability_vulnerability(&self) -> Option<usize> {
        // Pattern: ECRECOVER without s-value range check
        // Signature malleability through high s values
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x01 {  // ECRECOVER
                let mut checks_s_value = false;
                
                // Check for s-value range validation (s < secp256k1n/2)
                for j in (i.saturating_sub(25))..i {
                    // s parameter should be checked against half curve order
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD (s value)
                        for k in j+1..(j+20).min(self.bytecode.len()) {
                            // Check s is in lower half (prevents malleability)
                            if self.bytecode[k] == 0x10 {  // LT (s < max)
                                checks_s_value = true;
                            }
                        }
                    }
                }
                
                if !checks_s_value {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_hash_algorithm_downgrade(&self) -> Option<usize> {
        // Pattern: Hash algorithm selection from untrusted source
        // SHA3 vs other hash choice controlled by input
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x20 {  // SHA3
                let mut has_alternative = false;
                let mut validates_choice = false;
                
                // Check if there are multiple hash paths
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Look for conditional hashing (JUMPI around SHA3)
                    if self.bytecode[j] == 0x57 {  // JUMPI
                        has_alternative = true;
                    }
                }
                
                // Check if hash choice is validated
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD (hash choice)
                        for k in j+1..(j+15).min(self.bytecode.len()) {
                            // Whitelist check
                            if self.bytecode[k] == 0x14 {  // EQ (allowed algorithm)
                                validates_choice = true;
                            }
                        }
                    }
                }
                
                if has_alternative && !validates_choice {
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
                    format!("SignatureSchemeDowngrade{:?}", v.vulnerability_type)
                ),
                severity: v.severity,
                pc: v.location as u64,
                description: format!(
                    "Signature Scheme Downgrade {:?}: {}",
                    v.vulnerability_type, v.description
                ),
                operations: Vec::new(),
                remediation: "Enforce single strong signature scheme (secp256k1 with SHA256/Keccak256), \
                             validate signature lengths (65 bytes), check s-value range for malleability \
                             prevention, validate curve parameters, and use algorithm whitelists".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weaker_signature_forcing() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x01, // ECRECOVER (first scheme)
            0x60, 0x01, // PUSH1 1
            0x01, // ECRECOVER (second scheme - no validation)
        ];
        
        let detector = SignatureSchemeDowngradeDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, SignatureDowngradeType::WeakerSignatureForcing)));
    }

    #[test]
    fn test_malleability_vulnerability() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x35, // CALLDATALOAD (signature)
            0x01, // ECRECOVER (without s-value check)
        ];
        
        let detector = SignatureSchemeDowngradeDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, SignatureDowngradeType::MalleabilityVulnerability)));
    }
}
