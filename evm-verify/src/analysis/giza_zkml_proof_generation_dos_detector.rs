// Giza zkML Proof Generation DOS Detector
// Detects DoS vulnerabilities in zkML proof generation systems

use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GizaZKMLVulnerability {
    pub location: usize,
    pub vulnerability_type: GizaVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GizaVulnerabilityType {
    ProofGenerationDOS,             // DoS proof generation with expensive inputs
    CircuitComplexityExploit,       // Exploit circuit complexity limits
    WitnessGenerationGriefing,      // Grief witness generation process
    VerifierGasExhaustion,          // Exhaust verifier gas with crafted proofs
    ProofCachingBypass,             // Bypass proof result caching
    ModelQuantizationAttack,        // Attack quantized model precision
    InferenceTimeoutExploit,        // Cause inference timeout
}

pub struct GizaZKMLDetector {
    bytecode: Vec<u8>,
}

impl GizaZKMLDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<GizaZKMLVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_proof_generation_dos() {
            vulnerabilities.push(GizaZKMLVulnerability {
                location: loc,
                vulnerability_type: GizaVulnerabilityType::ProofGenerationDOS,
                severity: SecuritySeverity::High,
                description: "Proof generation accepts unbounded input size. Attacker can submit \
                             massive inputs causing proof generation to timeout or consume excessive resources.".to_string(),
                confidence: 0.85,
            });
        }

        if let Some(loc) = self.detect_circuit_complexity_exploit() {
            vulnerabilities.push(GizaZKMLVulnerability {
                location: loc,
                vulnerability_type: GizaVulnerabilityType::CircuitComplexityExploit,
                severity: SecuritySeverity::High,
                description: "Circuit complexity not validated before proof generation. Adversarial \
                             inputs can create circuits exceeding prover capacity.".to_string(),
                confidence: 0.82,
            });
        }

        if let Some(loc) = self.detect_witness_griefing() {
            vulnerabilities.push(GizaZKMLVulnerability {
                location: loc,
                vulnerability_type: GizaVulnerabilityType::WitnessGenerationGriefing,
                severity: SecuritySeverity::Medium,
                description: "Witness generation lacks timeout. Malicious input can cause infinite \
                             loops or excessive computation in witness generation phase.".to_string(),
                confidence: 0.78,
            });
        }

        if let Some(loc) = self.detect_verifier_gas_exhaustion() {
            vulnerabilities.push(GizaZKMLVulnerability {
                location: loc,
                vulnerability_type: GizaVulnerabilityType::VerifierGasExhaustion,
                severity: SecuritySeverity::High,
                description: "Proof verification gas cost not bounded. Crafted proofs can cause \
                             verification to consume excessive gas, DoS the verifier.".to_string(),
                confidence: 0.84,
            });
        }

        if let Some(loc) = self.detect_cache_bypass() {
            vulnerabilities.push(GizaZKMLVulnerability {
                location: loc,
                vulnerability_type: GizaVulnerabilityType::ProofCachingBypass,
                severity: SecuritySeverity::Medium,
                description: "Proof result caching uses weak key. Attacker can submit slightly \
                             modified inputs to bypass cache and force repeated expensive proofs.".to_string(),
                confidence: 0.74,
            });
        }

        if let Some(loc) = self.detect_quantization_attack() {
            vulnerabilities.push(GizaZKMLVulnerability {
                location: loc,
                vulnerability_type: GizaVulnerabilityType::ModelQuantizationAttack,
                severity: SecuritySeverity::Medium,
                description: "Model quantization bounds not enforced. Adversarial inputs can exploit \
                             quantization errors to produce incorrect inference results.".to_string(),
                confidence: 0.76,
            });
        }

        if let Some(loc) = self.detect_timeout_exploit() {
            vulnerabilities.push(GizaZKMLVulnerability {
                location: loc,
                vulnerability_type: GizaVulnerabilityType::InferenceTimeoutExploit,
                severity: SecuritySeverity::Medium,
                description: "Inference lacks execution time limit. Complex inputs can cause \
                             inference to run indefinitely, locking resources.".to_string(),
                confidence: 0.72,
            });
        }

        vulnerabilities
    }

    fn detect_proof_generation_dos(&self) -> Option<usize> {
        // Pattern: Input size not checked before proof generation
        // CALLDATASIZE → no comparison → proof generation call
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x36 {  // CALLDATASIZE
                let mut has_size_limit = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT (size check)
                        has_size_limit = true;
                    }
                    
                    // Proof generation without size check
                    if !has_size_limit && (self.bytecode[j] == 0xF1 || self.bytecode[j] == 0xFA) {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_circuit_complexity_exploit(&self) -> Option<usize> {
        // Pattern: Circuit construction without complexity validation
        // Loop building circuit without iteration limit
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x5B {  // JUMPDEST (loop)
                let mut has_complexity_bound = false;
                let mut builds_circuit = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Circuit building (SSTOREs or CALLs)
                    if self.bytecode[j] == 0x55 || self.bytecode[j] == 0xF1 {
                        builds_circuit = true;
                    }
                    
                    // Complexity bound check
                    if self.bytecode[j] == 0x10 && builds_circuit {  // LT (counter < max)
                        has_complexity_bound = true;
                    }
                    
                    if builds_circuit && !has_complexity_bound && self.bytecode[j] == 0x57 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_witness_griefing(&self) -> Option<usize> {
        // Pattern: Witness generation without gas/time limit
        // Computation loop without GAS opcode check
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x5B {  // JUMPDEST
                let mut has_gas_check = false;
                let mut has_computation = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Computation operations
                    if matches!(self.bytecode[j], 0x01..=0x0B) {  // Arithmetic ops
                        has_computation = true;
                    }
                    
                    if self.bytecode[j] == 0x5A {  // GAS
                        has_gas_check = true;
                    }
                    
                    if has_computation && !has_gas_check && self.bytecode[j] == 0x57 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_verifier_gas_exhaustion(&self) -> Option<usize> {
        // Pattern: Verification loop without gas limit
        // STATICCALL (verify) in loop without gas check
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (verify component)
                // Check if in loop context
                let mut in_loop = false;
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x5B {  // JUMPDEST
                        in_loop = true;
                    }
                }
                
                if in_loop {
                    let mut has_gas_limit = false;
                    for j in i+1..(i+20).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x5A {  // GAS check
                            has_gas_limit = true;
                        }
                    }
                    
                    if !has_gas_limit {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_cache_bypass(&self) -> Option<usize> {
        // Pattern: Cache key without cryptographic hash
        // Storage key calculation without SHA3
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x54 {  // SLOAD (check cache)
                let mut uses_strong_key = false;
                
                // Check if key uses hash
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x20 {  // SHA3
                        uses_strong_key = true;
                    }
                }
                
                // Check if this looks like proof result cache
                let mut is_proof_cache = false;
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x15 {  // ISZERO (cache miss)
                        is_proof_cache = true;
                    }
                }
                
                if is_proof_cache && !uses_strong_key {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_quantization_attack(&self) -> Option<usize> {
        // Pattern: Quantization without bounds checking
        // DIV/MUL (quantize) without range validation
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x04 || self.bytecode[i] == 0x02 {  // DIV/MUL
                let mut has_bounds_check = false;
                
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT
                        has_bounds_check = true;
                    }
                    
                    // Quantized value used without validation
                    if !has_bounds_check && self.bytecode[j] == 0x55 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_timeout_exploit(&self) -> Option<usize> {
        // Pattern: Inference without timeout
        // Execution loop without TIMESTAMP delta check
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x5B {  // JUMPDEST (inference loop)
                let mut has_timeout = false;
                let mut has_inference_ops = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Inference operations (arithmetic/calls)
                    if matches!(self.bytecode[j], 0x01..=0x0B) || self.bytecode[j] == 0xF1 {
                        has_inference_ops = true;
                    }
                    
                    // Timeout check: TIMESTAMP → SUB → LT
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x03 {  // SUB (delta)
                                has_timeout = true;
                            }
                        }
                    }
                    
                    if has_inference_ops && !has_timeout && self.bytecode[j] == 0x57 {
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
                kind: SecurityWarningKind::GizaZkML,
                severity: v.severity,
                description: format!(
                    "Giza zkML {:?} at PC {}: {}",
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
    fn test_proof_generation_dos() {
        let bytecode = vec![
            0x36, // CALLDATASIZE
            0x60, 0x00, // PUSH1 0
            0xF1, // CALL (generate proof without size check)
        ];
        
        let detector = GizaZKMLDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, GizaVulnerabilityType::ProofGenerationDOS)));
    }

    #[test]
    fn test_witness_griefing() {
        let bytecode = vec![
            0x5B, // JUMPDEST (loop)
            0x01, // ADD (computation)
            0x60, 0x00, // PUSH1 0
            0x57, // JUMPI (no gas check)
        ];
        
        let detector = GizaZKMLDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, GizaVulnerabilityType::WitnessGenerationGriefing)));
    }
}
