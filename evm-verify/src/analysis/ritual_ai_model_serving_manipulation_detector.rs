// Ritual AI Model Serving Manipulation Detector
// Detects manipulation in decentralized AI inference services

use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RitualAIVulnerability {
    pub location: usize,
    pub vulnerability_type: RitualVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RitualVulnerabilityType {
    InferenceResultManipulation,    // Manipulate model output
    ModelWeightPoisoning,           // Poison model weights
    ComputationVerificationBypass,  // Bypass proof of computation
    InputDataLeakage,               // Leak private inference inputs
    ModelIPTheft,                   // Steal proprietary model weights
    InferencePricingExploit,        // Manipulate inference pricing
    BatchRequestDOS,                // DoS through batch requests
}

pub struct RitualAIDetector {
    bytecode: Vec<u8>,
}

impl RitualAIDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<RitualAIVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_result_manipulation() {
            vulnerabilities.push(RitualAIVulnerability {
                location: loc,
                vulnerability_type: RitualVulnerabilityType::InferenceResultManipulation,
                severity: SecuritySeverity::Critical,
                description: "Inference result not cryptographically verified. Node can return \
                             arbitrary results without detection, breaking trust model.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_weight_poisoning() {
            vulnerabilities.push(RitualAIVulnerability {
                location: loc,
                vulnerability_type: RitualVulnerabilityType::ModelWeightPoisoning,
                severity: SecuritySeverity::High,
                description: "Model weight updates lack validation. Malicious node can poison model \
                             by submitting crafted weight gradients.".to_string(),
                confidence: 0.84,
            });
        }

        if let Some(loc) = self.detect_computation_bypass() {
            vulnerabilities.push(RitualAIVulnerability {
                location: loc,
                vulnerability_type: RitualVulnerabilityType::ComputationVerificationBypass,
                severity: SecuritySeverity::Critical,
                description: "Proof of computation not enforced. Node can claim inference performed \
                             without actually running computation.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_input_leakage() {
            vulnerabilities.push(RitualAIVulnerability {
                location: loc,
                vulnerability_type: RitualVulnerabilityType::InputDataLeakage,
                severity: SecuritySeverity::High,
                description: "Inference input stored without encryption. Private data exposed to \
                             inference nodes, breaking confidentiality.".to_string(),
                confidence: 0.81,
            });
        }

        if let Some(loc) = self.detect_model_ip_theft() {
            vulnerabilities.push(RitualAIVulnerability {
                location: loc,
                vulnerability_type: RitualVulnerabilityType::ModelIPTheft,
                severity: SecuritySeverity::High,
                description: "Model weights transmitted without protection. Inference node can \
                             extract proprietary model architecture and weights.".to_string(),
                confidence: 0.79,
            });
        }

        if let Some(loc) = self.detect_pricing_exploit() {
            vulnerabilities.push(RitualAIVulnerability {
                location: loc,
                vulnerability_type: RitualVulnerabilityType::InferencePricingExploit,
                severity: SecuritySeverity::Medium,
                description: "Inference pricing based on claimed complexity. Node can underreport \
                             computation cost to undercut competitors unfairly.".to_string(),
                confidence: 0.75,
            });
        }

        if let Some(loc) = self.detect_batch_dos() {
            vulnerabilities.push(RitualAIVulnerability {
                location: loc,
                vulnerability_type: RitualVulnerabilityType::BatchRequestDOS,
                severity: SecuritySeverity::Medium,
                description: "Batch inference requests unbounded. Attacker can submit massive batch \
                             to DoS inference service.".to_string(),
                confidence: 0.73,
            });
        }

        vulnerabilities
    }

    fn detect_result_manipulation(&self) -> Option<usize> {
        // Pattern: Result stored without ZK proof verification
        // CALLDATALOAD (result) → SSTORE without proof check
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (inference result)
                let mut has_proof_verification = false;
                
                // Check for ZK proof verification
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xFA {  // CALL (verify proof)
                        has_proof_verification = true;
                    }
                }
                
                // Result stored without verification
                if !has_proof_verification {
                    for j in i+1..(i+20).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 {  // SSTORE
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_weight_poisoning(&self) -> Option<usize> {
        // Pattern: Weight update without bounds checking
        // CALLDATALOAD (gradient) → ADD/SUB (update) without validation
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (gradient/weight)
                let mut has_bounds_check = false;
                let mut has_update = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x01 || self.bytecode[j] == 0x03 {  // ADD/SUB
                        has_update = true;
                    }
                    
                    // Bounds validation
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT
                        has_bounds_check = true;
                    }
                    
                    // Weight update without validation
                    if has_update && !has_bounds_check && self.bytecode[j] == 0x55 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_computation_bypass(&self) -> Option<usize> {
        // Pattern: Reward payout without proof verification
        // CALL (pay node) without prior proof check
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xF1 {  // CALL (payment)
                let mut verified_computation = false;
                
                // Check for proof verification before payment
                for j in (i.saturating_sub(25))..i {
                    if self.bytecode[j] == 0xFA {  // STATICCALL (verify proof)
                        // Check result is used
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 {  // ISZERO (check success)
                                verified_computation = true;
                            }
                        }
                    }
                }
                
                // Check if this looks like inference payment (multiple value ops before)
                let mut value_ops = 0;
                for j in (i.saturating_sub(15))..i {
                    if matches!(self.bytecode[j], 0x60..=0x7F) {  // PUSH
                        value_ops += 1;
                    }
                }
                
                if value_ops >= 2 && !verified_computation {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_input_leakage(&self) -> Option<usize> {
        // Pattern: Input data stored in cleartext
        // CALLDATALOAD → SSTORE without encryption
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (input)
                let mut is_encrypted = false;
                
                // Check for encryption (CALL to encryption contract or SHA3)
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x20 || self.bytecode[j] == 0xF1 {  // SHA3 or CALL
                        is_encrypted = true;
                    }
                }
                
                // Input stored without encryption
                if !is_encrypted {
                    for j in i+1..(i+12).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 {  // SSTORE
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_model_ip_theft(&self) -> Option<usize> {
        // Pattern: Model weights transmitted without commitment
        // SLOAD (weights) → MSTORE/RETURN without hash commitment
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x54 {  // SLOAD (model weight)
                let mut has_commitment = false;
                
                // Check for commitment scheme (hash before transmission)
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x20 {  // SHA3 (commitment)
                        has_commitment = true;
                    }
                }
                
                // Weights returned without protection
                if !has_commitment {
                    for j in i+1..(i+20).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x52 || self.bytecode[j] == 0xF3 {  // MSTORE/RETURN
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_pricing_exploit(&self) -> Option<usize> {
        // Pattern: Price calculation without verification
        // CALLDATALOAD (complexity claim) → MUL (price) without validation
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (complexity)
                let mut validates_complexity = false;
                
                // Check for complexity validation
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Validation: comparison against limits
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT
                        validates_complexity = true;
                    }
                }
                
                // Price calculated from unvalidated input
                if !validates_complexity {
                    for j in i+1..(i+15).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x02 {  // MUL (calculate price)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_batch_dos(&self) -> Option<usize> {
        // Pattern: Batch processing without size limit
        // Loop over inputs without max iteration check
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x5B {  // JUMPDEST (loop)
                let mut has_iteration_limit = false;
                let mut has_calldataload = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD (batch item)
                        has_calldataload = true;
                    }
                    
                    // Iteration limit: counter compared against max
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT
                        has_iteration_limit = true;
                    }
                    
                    // Loop without limit
                    if has_calldataload && !has_iteration_limit && self.bytecode[j] == 0x57 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    pub fn to_security_warnings(&self) -> Vec<SecurityWarning> {
        self.detect()
            .into_iter()
            .map(|v| SecurityWarning {
                kind: SecurityWarningKind::RitualAI,
                severity: v.severity,
                description: format!(
                    "Ritual AI {:?} at PC {}: {}",
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
    fn test_result_manipulation() {
        let bytecode = vec![
            0x35, // CALLDATALOAD (inference result)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (no proof verification)
        ];
        
        let detector = RitualAIDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, RitualVulnerabilityType::InferenceResultManipulation)));
    }

    #[test]
    fn test_input_leakage() {
        let bytecode = vec![
            0x35, // CALLDATALOAD (private input)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (stored without encryption)
        ];
        
        let detector = RitualAIDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, RitualVulnerabilityType::InputDataLeakage)));
    }
}
