// EZKL Model Commitment Manipulation Detector
// Detects manipulation in EZKL zkML model commitments and verification

use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EZKLVulnerability {
    pub location: usize,
    pub vulnerability_type: EZKLVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EZKLVulnerabilityType {
    ModelCommitmentForging,         // Forge model commitment
    ProofVerificationBypass,        // Bypass proof verification
    InputPreprocessingExploit,      // Exploit preprocessing stage
    OutputPostprocessingManipulation, // Manipulate output processing
    SettingsFileInconsistency,      // Settings file mismatch
    CircuitSizeMismatch,            // Circuit size doesn't match model
}

pub struct EZKLDetector {
    bytecode: Vec<u8>,
}

impl EZKLDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<EZKLVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_commitment_forging() {
            vulnerabilities.push(EZKLVulnerability {
                location: loc,
                vulnerability_type: EZKLVulnerabilityType::ModelCommitmentForging,
                severity: SecuritySeverity::Critical,
                description: "Model commitment uses weak hash. Attacker can find collision to \
                             substitute malicious model with same commitment hash.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_verification_bypass() {
            vulnerabilities.push(EZKLVulnerability {
                location: loc,
                vulnerability_type: EZKLVulnerabilityType::ProofVerificationBypass,
                severity: SecuritySeverity::Critical,
                description: "Proof verification result not checked. Failed verification still \
                             allows inference result to be accepted and used.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_preprocessing_exploit() {
            vulnerabilities.push(EZKLVulnerability {
                location: loc,
                vulnerability_type: EZKLVulnerabilityType::InputPreprocessingExploit,
                severity: SecuritySeverity::High,
                description: "Input preprocessing lacks bounds validation. Adversarial inputs can \
                             exploit preprocessing to produce out-of-range circuit values.".to_string(),
                confidence: 0.83,
            });
        }

        if let Some(loc) = self.detect_postprocessing_manipulation() {
            vulnerabilities.push(EZKLVulnerability {
                location: loc,
                vulnerability_type: EZKLVulnerabilityType::OutputPostprocessingManipulation,
                severity: SecuritySeverity::High,
                description: "Output postprocessing applied after proof verification. Results can \
                             be manipulated without invalidating proof.".to_string(),
                confidence: 0.81,
            });
        }

        if let Some(loc) = self.detect_settings_inconsistency() {
            vulnerabilities.push(EZKLVulnerability {
                location: loc,
                vulnerability_type: EZKLVulnerabilityType::SettingsFileInconsistency,
                severity: SecuritySeverity::High,
                description: "Settings file hash not verified against commitment. Inference can run \
                             with different settings than model was calibrated with.".to_string(),
                confidence: 0.78,
            });
        }

        if let Some(loc) = self.detect_circuit_size_mismatch() {
            vulnerabilities.push(EZKLVulnerability {
                location: loc,
                vulnerability_type: EZKLVulnerabilityType::CircuitSizeMismatch,
                severity: SecuritySeverity::Medium,
                description: "Circuit size not validated against model specification. Smaller circuit \
                             can be used reducing security guarantees.".to_string(),
                confidence: 0.75,
            });
        }

        vulnerabilities
    }

    fn detect_commitment_forging(&self) -> Option<usize> {
        // Pattern: Model commitment using simple hash without salt
        // SHA3 alone → SSTORE without additional binding
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x20 {  // SHA3
                let mut has_salt = false;
                let mut has_signature = false;
                
                // Check for salt (additional input to hash)
                for j in (i.saturating_sub(15))..i {
                    // Multiple inputs (at least 3: model + salt + ...)
                    let push_count = (i.saturating_sub(15)..i)
                        .filter(|&k| matches!(self.bytecode[k], 0x60..=0x7F) || self.bytecode[k] == 0x35)
                        .count();
                    if push_count >= 3 {
                        has_salt = true;
                    }
                }
                
                // Check for signature after hash
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xFA {  // Signature verification
                        has_signature = true;
                    }
                }
                
                // Weak commitment
                if !has_salt && !has_signature {
                    for j in i+1..(i+10).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_verification_bypass(&self) -> Option<usize> {
        // Pattern: Verification call result ignored
        // STATICCALL (verify) → POP or not checked
        
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (verify proof)
                let mut checks_result = false;
                
                for j in i+1..(i+12).min(self.bytecode.len()) {
                    // Result check: ISZERO → REVERT or JUMPI
                    if self.bytecode[j] == 0x15 {  // ISZERO
                        for k in j+1..(j+3).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0xFD || self.bytecode[k] == 0x57 {
                                checks_result = true;
                            }
                        }
                    }
                    
                    // Result popped (ignored)
                    if self.bytecode[j] == 0x50 {  // POP
                        if !checks_result {
                            return Some(i);
                        }
                    }
                }
                
                // Result not used at all
                if !checks_result {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_preprocessing_exploit(&self) -> Option<usize> {
        // Pattern: Input transformation without bounds check
        // MUL/DIV/ADD (preprocess) → use without validation
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if matches!(self.bytecode[i], 0x01..=0x05) {  // ADD/MUL/SUB/DIV/MOD
                let mut has_bounds_check = false;
                let mut has_input_load = false;
                
                // Check if processing input
                for j in (i.saturating_sub(10))..i {
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD
                        has_input_load = true;
                    }
                }
                
                // Check for bounds validation
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT
                        has_bounds_check = true;
                    }
                    
                    // Preprocessed input used without bounds
                    if has_input_load && !has_bounds_check && self.bytecode[j] == 0x55 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_postprocessing_manipulation(&self) -> Option<usize> {
        // Pattern: Postprocessing after verification instead of before
        // STATICCALL (verify) → arithmetic ops → SSTORE
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (verify)
                let mut has_postprocessing = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Postprocessing operations after verification
                    if matches!(self.bytecode[j], 0x01..=0x05) {  // Arithmetic
                        has_postprocessing = true;
                    }
                    
                    // Result stored after postprocessing
                    if has_postprocessing && self.bytecode[j] == 0x55 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_settings_inconsistency(&self) -> Option<usize> {
        // Pattern: Settings used without hash verification
        // SLOAD (settings) → use without hash comparison
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x54 {  // SLOAD (settings)
                let mut verifies_hash = false;
                
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    // Hash verification
                    if self.bytecode[j] == 0x20 {  // SHA3
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (compare hash)
                                verifies_hash = true;
                            }
                        }
                    }
                }
                
                // Settings used without verification
                if !verifies_hash {
                    for j in i+1..(i+12).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xF1 {  // Used in computation
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_circuit_size_mismatch(&self) -> Option<usize> {
        // Pattern: Circuit size not validated
        // Proof verification without size check
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (verify)
                let mut validates_size = false;
                
                // Check for size validation before verification
                for j in (i.saturating_sub(20))..i {
                    // Size check: CALLDATASIZE or length comparison
                    if self.bytecode[j] == 0x36 {  // CALLDATASIZE
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (exact size)
                                validates_size = true;
                            }
                        }
                    }
                }
                
                if !validates_size {
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
                kind: SecurityWarningKind::EZKL,
                severity: v.severity,
                description: format!(
                    "EZKL {:?} at PC {}: {}",
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
    fn test_commitment_forging() {
        let bytecode = vec![
            0x60, 0x00, // PUSH1 0
            0x20, // SHA3 (simple hash)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (no salt/signature)
        ];
        
        let detector = EZKLDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, EZKLVulnerabilityType::ModelCommitmentForging)));
    }

    #[test]
    fn test_verification_bypass() {
        let bytecode = vec![
            0xFA, // STATICCALL (verify)
            0x50, // POP (ignore result)
        ];
        
        let detector = EZKLDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, EZKLVulnerabilityType::ProofVerificationBypass)));
    }
}
