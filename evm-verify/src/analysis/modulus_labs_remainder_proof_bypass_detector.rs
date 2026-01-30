// Modulus Labs Remainder Proof Bypass Detector
// Detects bypasses in zkML remainder proof systems

use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModulusLabsVulnerability {
    pub location: usize,
    pub vulnerability_type: ModulusVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ModulusVulnerabilityType {
    RemainderProofBypass,           // Bypass remainder proof verification
    ModulusOperationExploit,        // Exploit modular arithmetic
    RangeProofIncomplete,           // Incomplete range proof verification
    CommitmentSchemeWeakness,       // Weak commitment verification
    WitnessReplayAttack,            // Replay old witness data
    CircuitConstraintBypass,        // Bypass circuit constraints
}

pub struct ModulusLabsDetector {
    bytecode: Vec<u8>,
}

impl ModulusLabsDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ModulusLabsVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_remainder_proof_bypass() {
            vulnerabilities.push(ModulusLabsVulnerability {
                location: loc,
                vulnerability_type: ModulusVulnerabilityType::RemainderProofBypass,
                severity: SecuritySeverity::Critical,
                description: "Remainder proof verification incomplete. Missing checks allow invalid \
                             remainders to pass verification, breaking zkML correctness.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_modulus_exploit() {
            vulnerabilities.push(ModulusLabsVulnerability {
                location: loc,
                vulnerability_type: ModulusVulnerabilityType::ModulusOperationExploit,
                severity: SecuritySeverity::High,
                description: "Modular arithmetic lacks bounds checking. Adversarial inputs can \
                             cause overflow in modulus operations leading to incorrect results.".to_string(),
                confidence: 0.83,
            });
        }

        if let Some(loc) = self.detect_range_proof_incomplete() {
            vulnerabilities.push(ModulusLabsVulnerability {
                location: loc,
                vulnerability_type: ModulusVulnerabilityType::RangeProofIncomplete,
                severity: SecuritySeverity::High,
                description: "Range proof verification missing components. Values outside valid range \
                             can be used in computation without detection.".to_string(),
                confidence: 0.85,
            });
        }

        if let Some(loc) = self.detect_commitment_weakness() {
            vulnerabilities.push(ModulusLabsVulnerability {
                location: loc,
                vulnerability_type: ModulusVulnerabilityType::CommitmentSchemeWeakness,
                severity: SecuritySeverity::High,
                description: "Commitment verification uses weak binding. Prover can open commitment \
                             to different value than committed, breaking soundness.".to_string(),
                confidence: 0.81,
            });
        }

        if let Some(loc) = self.detect_witness_replay() {
            vulnerabilities.push(ModulusLabsVulnerability {
                location: loc,
                vulnerability_type: ModulusVulnerabilityType::WitnessReplayAttack,
                severity: SecuritySeverity::Medium,
                description: "Witness data lacks freshness validation. Old witness can be replayed \
                             to bypass re-computation of inference results.".to_string(),
                confidence: 0.76,
            });
        }

        if let Some(loc) = self.detect_constraint_bypass() {
            vulnerabilities.push(ModulusLabsVulnerability {
                location: loc,
                vulnerability_type: ModulusVulnerabilityType::CircuitConstraintBypass,
                severity: SecuritySeverity::Critical,
                description: "Circuit constraints not fully verified. Prover can satisfy subset of \
                             constraints while violating others, producing invalid proofs.".to_string(),
                confidence: 0.84,
            });
        }

        vulnerabilities
    }

    fn detect_remainder_proof_bypass(&self) -> Option<usize> {
        // Pattern: MOD operation result used without proof verification
        // MOD → use without STATICCALL (verify proof)
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x06 {  // MOD
                let mut has_proof_verification = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xFA {  // STATICCALL (verify remainder proof)
                        has_proof_verification = true;
                    }
                }
                
                // Remainder used without proof
                if !has_proof_verification {
                    for j in i+1..(i+15).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 || self.bytecode[j] == 0x52 {  // SSTORE/MSTORE
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_modulus_exploit(&self) -> Option<usize> {
        // Pattern: Modular arithmetic without overflow protection
        // ADD/MUL → MOD without overflow check
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x01 || self.bytecode[i] == 0x02 {  // ADD/MUL
                let mut has_overflow_check = false;
                let mut has_mod = false;
                
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x06 {  // MOD
                        has_mod = true;
                    }
                    
                    // Overflow check before MOD
                    if matches!(self.bytecode[j], 0x80..=0x8F) ||  // DUP
                       matches!(self.bytecode[j], 0x10 | 0x11) {   // LT/GT
                        has_overflow_check = true;
                    }
                }
                
                if has_mod && !has_overflow_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_range_proof_incomplete(&self) -> Option<usize> {
        // Pattern: Value used without range proof verification
        // CALLDATALOAD → use without range check call
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD
                let mut has_range_verification = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Range proof verification
                    if self.bytecode[j] == 0xFA {  // STATICCALL
                        has_range_verification = true;
                    }
                    
                    // Simple LT/GT is not enough, need cryptographic proof
                    if !has_range_verification && self.bytecode[j] == 0x55 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_commitment_weakness(&self) -> Option<usize> {
        // Pattern: Commitment opening without binding check
        // SHA3 (commitment) → EQ (check) without additional validation
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x20 {  // SHA3 (compute commitment)
                let mut has_simple_check = false;
                let mut has_binding_verification = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 {  // EQ (simple equality)
                        has_simple_check = true;
                    }
                    
                    // Binding verification: additional proof check
                    if self.bytecode[j] == 0xFA && has_simple_check {  // STATICCALL after EQ
                        has_binding_verification = true;
                    }
                }
                
                // Simple equality without binding proof
                if has_simple_check && !has_binding_verification {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_witness_replay(&self) -> Option<usize> {
        // Pattern: Witness data without timestamp/nonce validation
        // SLOAD (witness) → use without freshness check
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x54 {  // SLOAD (witness data)
                let mut checks_freshness = false;
                
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    // Freshness: TIMESTAMP or block.number comparison
                    if self.bytecode[j] == 0x42 || self.bytecode[j] == 0x43 {  // TIMESTAMP/NUMBER
                        checks_freshness = true;
                    }
                }
                
                // Witness used without freshness
                if !checks_freshness {
                    for j in i+1..(i+12).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xF1 || self.bytecode[j] == 0x55 {
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_constraint_bypass(&self) -> Option<usize> {
        // Pattern: Partial constraint verification
        // Single STATICCALL (verify) for multiple constraints
        
        let mut verify_call_count = 0;
        let mut constraint_count = 0;
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Count verification calls
            if self.bytecode[i] == 0xFA {  // STATICCALL (verify)
                verify_call_count += 1;
            }
            
            // Count constraints (arithmetic operations that need verification)
            if matches!(self.bytecode[i], 0x01..=0x0B) {  // Arithmetic
                constraint_count += 1;
            }
            
            // Check window of 40 bytes
            if i % 40 == 39 && constraint_count > 5 && verify_call_count < 2 {
                return Some(i - 39);
            }
            
            if i % 40 == 39 {
                verify_call_count = 0;
                constraint_count = 0;
            }
        }
        
        None
    }

    pub fn to_security_warnings(&self) -> Vec<SecurityWarning> {
        self.detect()
            .into_iter()
            .map(|v| SecurityWarning {
                kind: SecurityWarningKind::ModulusLabs,
                severity: v.severity,
                description: format!(
                    "Modulus Labs {:?} at PC {}: {}",
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
    fn test_remainder_proof_bypass() {
        let bytecode = vec![
            0x06, // MOD (remainder)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (use without proof)
        ];
        
        let detector = ModulusLabsDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, ModulusVulnerabilityType::RemainderProofBypass)));
    }

    #[test]
    fn test_modulus_overflow() {
        let bytecode = vec![
            0x02, // MUL
            0x60, 0xFF, // PUSH1 255
            0x06, // MOD (no overflow check)
        ];
        
        let detector = ModulusLabsDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, ModulusVulnerabilityType::ModulusOperationExploit)));
    }
}
