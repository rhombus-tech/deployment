// ZK Rollup Proof Generation DOS Detector
// Detects sequencer compute exhaustion through expensive proof generation

use crate::bytecode::security::{SecuritySeverity, SecurityWarning};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKRollupDOSVulnerability {
    pub location: usize,
    pub vulnerability_type: ZKRollupDOSType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZKRollupDOSType {
    CircuitComplexityExploitation,   // Force expensive circuit execution
    WitnessGenerationGriefing,       // Craft inputs requiring excessive witness generation
    ProverResourceExhaustion,        // Exhaust prover memory/CPU
    BatchSizeManipulation,           // Force small batches increasing cost per tx
    VerificationGasExhaustion,       // On-chain verification gas DOS
    ProofAggregationBottleneck,      // Prevent efficient proof aggregation
}

pub struct ZKRollupDOSDetector {
    bytecode: Vec<u8>,
}

impl ZKRollupDOSDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<ZKRollupDOSVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_circuit_complexity_exploitation() {
            vulnerabilities.push(ZKRollupDOSVulnerability {
                location: loc,
                vulnerability_type: ZKRollupDOSType::CircuitComplexityExploitation,
                severity: SecuritySeverity::High,
                description: "Transaction validation lacks circuit complexity limits. Adversarial \
                             transactions can force expensive constraint generation.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_witness_generation_griefing() {
            vulnerabilities.push(ZKRollupDOSVulnerability {
                location: loc,
                vulnerability_type: ZKRollupDOSType::WitnessGenerationGriefing,
                severity: SecuritySeverity::Critical,
                description: "Witness generation unbounded. Crafted inputs can require exponential \
                             time to generate witnesses for proof system.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_prover_resource_exhaustion() {
            vulnerabilities.push(ZKRollupDOSVulnerability {
                location: loc,
                vulnerability_type: ZKRollupDOSType::ProverResourceExhaustion,
                severity: SecuritySeverity::Critical,
                description: "Prover lacks memory/computation limits. Adversarial batches can \
                             exhaust prover resources preventing block production.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_batch_size_manipulation() {
            vulnerabilities.push(ZKRollupDOSVulnerability {
                location: loc,
                vulnerability_type: ZKRollupDOSType::BatchSizeManipulation,
                severity: SecuritySeverity::Medium,
                description: "Batch size manipulable through griefing. Attacker can force small \
                             batches increasing per-transaction proving costs.".to_string(),
                confidence: 0.82,
            });
        }

        if let Some(loc) = self.detect_verification_gas_exhaustion() {
            vulnerabilities.push(ZKRollupDOSVulnerability {
                location: loc,
                vulnerability_type: ZKRollupDOSType::VerificationGasExhaustion,
                severity: SecuritySeverity::High,
                description: "On-chain proof verification gas cost unbounded. Adversarial proofs \
                             can exceed block gas limit preventing settlement.".to_string(),
                confidence: 0.85,
            });
        }

        if let Some(loc) = self.detect_proof_aggregation_bottleneck() {
            vulnerabilities.push(ZKRollupDOSVulnerability {
                location: loc,
                vulnerability_type: ZKRollupDOSType::ProofAggregationBottleneck,
                severity: SecuritySeverity::Medium,
                description: "Proof aggregation bypassable or inefficient. System cannot aggregate \
                             proofs efficiently increasing settlement costs.".to_string(),
                confidence: 0.79,
            });
        }

        vulnerabilities
    }

    fn detect_circuit_complexity_exploitation(&self) -> Option<usize> {
        // Pattern: Transaction processing without complexity bounds
        // No constraint counting or circuit depth limits
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (transaction data)
                let mut has_processing = false;
                let mut has_complexity_check = false;
                
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Processing (multiple operations indicating circuit execution)
                    if self.bytecode[j] == 0x20 || self.bytecode[j] == 0x01 {  // SHA3 or ADD
                        has_processing = true;
                    }
                    
                    // Complexity limit check (comparison against max constraints)
                    if self.bytecode[j] == 0x54 {  // SLOAD (constraint counter)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (under limit check)
                                has_complexity_check = true;
                            }
                        }
                    }
                }
                
                if has_processing && !has_complexity_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_witness_generation_griefing(&self) -> Option<usize> {
        // Pattern: Witness generation in loop without iteration limits
        // Unbounded witness computation
        
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x5B {  // JUMPDEST (loop)
                let mut has_witness_gen = false;
                let mut has_iteration_limit = false;
                
                for j in i+1..(i+30).min(self.bytecode.len()) {
                    // Witness generation (complex computation)
                    if self.bytecode[j] == 0x09 {  // MULMOD (field arithmetic)
                        has_witness_gen = true;
                    }
                    
                    // Iteration counter check
                    if self.bytecode[j] == 0x54 {  // SLOAD (iteration counter)
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (max iterations)
                                has_iteration_limit = true;
                            }
                        }
                    }
                    
                    // Backward jump
                    if self.bytecode[j] == 0x56 && has_witness_gen && !has_iteration_limit {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_prover_resource_exhaustion(&self) -> Option<usize> {
        // Pattern: Batch submission without prover resource checks
        // No memory or computation limits enforced
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 {  // SSTORE (batch submission)
                let mut is_batch = false;
                let mut has_resource_check = false;
                
                // Check if this is batch data (multiple sequential SSTOREs)
                let mut sstore_count = 1;
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 {
                        sstore_count += 1;
                    }
                }
                is_batch = sstore_count >= 3;
                
                // Check for resource limits (batch size, transaction count)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x10 || self.bytecode[j] == 0x11 {  // LT/GT (limit check)
                        has_resource_check = true;
                    }
                }
                
                if is_batch && !has_resource_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_batch_size_manipulation(&self) -> Option<usize> {
        // Pattern: Minimum batch size not enforced
        // Attacker can submit tiny batches
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Batch size check
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (batch data)
                let mut has_size_calc = false;
                let mut has_minimum_check = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Size calculation (DIV or MSIZE)
                    if self.bytecode[j] == 0x04 || self.bytecode[j] == 0x59 {
                        has_size_calc = true;
                    }
                    
                    // Minimum size enforcement
                    if self.bytecode[j] == 0x10 {  // LT (size > minimum)
                        has_minimum_check = true;
                    }
                }
                
                if has_size_calc && !has_minimum_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_verification_gas_exhaustion(&self) -> Option<usize> {
        // Pattern: Proof verification without gas limit checks
        // STATICCALL to verifier without gas stipend
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (proof verification)
                let mut has_gas_limit = false;
                
                // Check for explicit gas parameter (should be before STATICCALL)
                for j in (i.saturating_sub(15))..i {
                    // Gas limit specified (PUSH followed by GAS comparison)
                    if self.bytecode[j] == 0x60 || self.bytecode[j] == 0x61 {  // PUSH
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x5A {  // GAS
                                has_gas_limit = true;
                            }
                        }
                    }
                }
                
                if !has_gas_limit {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_proof_aggregation_bottleneck(&self) -> Option<usize> {
        // Pattern: Sequential proof processing without aggregation
        // Multiple proof verifications without batching
        
        let mut verification_count = 0;
        let mut has_aggregation = false;
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (verification)
                verification_count += 1;
                
                // Check for aggregation logic (combining multiple proofs)
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Aggregation pattern: multiple inputs combined
                    if self.bytecode[j] == 0x02 || self.bytecode[j] == 0x09 {  // MUL or MULMOD
                        has_aggregation = true;
                    }
                }
            }
        }
        
        // Multiple verifications without aggregation
        if verification_count >= 3 && !has_aggregation {
            return Some(0);
        }
        
        None
    }

    pub fn to_security_warnings(&self) -> Vec<SecurityWarning> {
        self.detect()
            .into_iter()
            .map(|v| SecurityWarning {
                kind: crate::bytecode::security::SecurityWarningKind::Other(
                    format!("ZKRollupDOS{:?}", v.vulnerability_type)
                ),
                severity: v.severity,
                pc: v.location as u64,
                description: format!(
                    "ZK Rollup DOS {:?}: {}",
                    v.vulnerability_type, v.description
                ),
                operations: Vec::new(),
                remediation: "Implement circuit complexity limits, witness generation bounds, \
                             prover resource caps, and minimum batch sizes".to_string(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_complexity_exploitation() {
        let bytecode = vec![
            0x35, // CALLDATALOAD
            0x20, // SHA3 (circuit operation)
            0x01, // ADD (more operations - no complexity check)
        ];
        
        let detector = ZKRollupDOSDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, ZKRollupDOSType::CircuitComplexityExploitation)));
    }

    #[test]
    fn test_witness_generation_griefing() {
        let bytecode = vec![
            0x5B, // JUMPDEST
            0x60, 0x00, // PUSH1 0
            0x09, // MULMOD (witness generation)
            0x56, // JUMP (loop back - no iteration limit)
        ];
        
        let detector = ZKRollupDOSDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, ZKRollupDOSType::WitnessGenerationGriefing)));
    }
}
