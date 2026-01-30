// Brevis ZK Coprocessor Result Caching Detector
// Detects manipulation in zkCoprocessor result caching mechanisms

use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrevisVulnerability {
    pub location: usize,
    pub vulnerability_type: BrevisVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BrevisVulnerabilityType {
    CacheKeyCollision,              // Cache key collision allows result spoofing
    ResultCacheBypass,              // Bypass cached result validation
    StaleResultUsage,               // Use outdated cached computation
    ProofReusability,               // Reuse proof for different inputs
    ComputationResultForging,       // Forge computation result
    CacheInvalidationFailure,       // Cache not invalidated when should be
}

pub struct BrevisDetector {
    bytecode: Vec<u8>,
}

impl BrevisDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<BrevisVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_cache_key_collision() {
            vulnerabilities.push(BrevisVulnerability {
                location: loc,
                vulnerability_type: BrevisVulnerabilityType::CacheKeyCollision,
                severity: SecuritySeverity::Critical,
                description: "Cache key uses weak hash allowing collisions. Attacker can craft inputs \
                             producing same cache key to inject malicious computation results.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_cache_bypass() {
            vulnerabilities.push(BrevisVulnerability {
                location: loc,
                vulnerability_type: BrevisVulnerabilityType::ResultCacheBypass,
                severity: SecuritySeverity::High,
                description: "Cached result used without proof verification. Cache hit bypasses ZK proof \
                             validation allowing unverified results.".to_string(),
                confidence: 0.85,
            });
        }

        if let Some(loc) = self.detect_stale_result() {
            vulnerabilities.push(BrevisVulnerability {
                location: loc,
                vulnerability_type: BrevisVulnerabilityType::StaleResultUsage,
                severity: SecuritySeverity::High,
                description: "Cache lacks expiration. Stale computation results used despite input data \
                             changes making cached result invalid.".to_string(),
                confidence: 0.83,
            });
        }

        if let Some(loc) = self.detect_proof_reuse() {
            vulnerabilities.push(BrevisVulnerability {
                location: loc,
                vulnerability_type: BrevisVulnerabilityType::ProofReusability,
                severity: SecuritySeverity::Critical,
                description: "Proof not bound to specific inputs. Same proof can be reused for different \
                             computations bypassing actual execution.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_result_forging() {
            vulnerabilities.push(BrevisVulnerability {
                location: loc,
                vulnerability_type: BrevisVulnerabilityType::ComputationResultForging,
                severity: SecuritySeverity::Critical,
                description: "Computation result not cryptographically bound to proof. Attacker can modify \
                             result while keeping valid proof.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_invalidation_failure() {
            vulnerabilities.push(BrevisVulnerability {
                location: loc,
                vulnerability_type: BrevisVulnerabilityType::CacheInvalidationFailure,
                severity: SecuritySeverity::Medium,
                description: "Cache not invalidated on input changes. Updated inputs still return old \
                             cached results instead of recomputing.".to_string(),
                confidence: 0.78,
            });
        }

        vulnerabilities
    }

    fn detect_cache_key_collision(&self) -> Option<usize> {
        // Pattern: Cache key using truncated hash or simple concatenation
        // SHA3 result truncated or simple addition used as key
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x20 {  // SHA3
                let mut key_truncated = false;
                
                // Check for truncation (AND with mask or MOD)
                for j in i+1..(i+10).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x16 || self.bytecode[j] == 0x06 {  // AND/MOD
                        key_truncated = true;
                    }
                }
                
                // Truncated hash used as cache key
                if key_truncated {
                    for j in i+1..(i+15).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 {  // SLOAD (cache lookup)
                            return Some(i);
                        }
                    }
                }
            }
            
            // Simple concatenation without hash
            if self.bytecode[i] == 0x01 {  // ADD (concatenate)
                let mut used_as_key = false;
                for j in i+1..(i+10).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 {  // SLOAD
                        used_as_key = true;
                    }
                }
                
                if used_as_key {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_cache_bypass(&self) -> Option<usize> {
        // Pattern: Cache hit without proof verification
        // SLOAD (cache) → ISZERO (miss check) → use without STATICCALL (verify)
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x54 {  // SLOAD (cache lookup)
                let mut checks_miss = false;
                let mut verifies_on_hit = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x15 {  // ISZERO (cache miss)
                        checks_miss = true;
                    }
                    
                    // Verification even on cache hit
                    if checks_miss && self.bytecode[j] == 0xFA {  // STATICCALL
                        verifies_on_hit = true;
                    }
                }
                
                // Cache hit bypasses verification
                if checks_miss && !verifies_on_hit {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_stale_result(&self) -> Option<usize> {
        // Pattern: Cache without timestamp/expiration check
        // Cached result used without age validation
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x54 {  // SLOAD (cached result)
                let mut checks_expiration = false;
                
                // Check for expiration validation
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x42 {  // TIMESTAMP
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (age check)
                                checks_expiration = true;
                            }
                        }
                    }
                }
                
                // Result used without expiration check
                if !checks_expiration {
                    for j in i+1..(i+12).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x52 || self.bytecode[j] == 0x55 {  // MSTORE/SSTORE
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_proof_reuse(&self) -> Option<usize> {
        // Pattern: Proof verification without input binding
        // STATICCALL (verify proof) without SHA3(inputs + proof)
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (verify)
                let mut binds_inputs = false;
                
                // Check for input binding (hash of inputs with proof)
                for j in (i.saturating_sub(20))..i {
                    if self.bytecode[j] == 0x20 {  // SHA3
                        // Check if multiple params hashed together
                        let param_count = (j.saturating_sub(15)..j)
                            .filter(|&k| matches!(self.bytecode[k], 0x35 | 0x54))
                            .count();
                        if param_count >= 2 {
                            binds_inputs = true;
                        }
                    }
                }
                
                if !binds_inputs {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_result_forging(&self) -> Option<usize> {
        // Pattern: Result not included in proof verification
        // Proof verified separately from result commitment
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (verify proof)
                let mut result_bound = false;
                
                // Check if result is part of verification
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Result binding: hash check after verification
                    if self.bytecode[j] == 0x20 {  // SHA3 (result)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (verify result hash)
                                result_bound = true;
                            }
                        }
                    }
                }
                
                // Result stored without binding to proof
                if !result_bound {
                    for j in i+1..(i+20).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 {  // SSTORE (result)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_invalidation_failure(&self) -> Option<usize> {
        // Pattern: Input update without cache invalidation
        // SSTORE (update input) without clearing related cache entries
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 {  // SSTORE (update input)
                let mut invalidates_cache = false;
                
                // Check for cache invalidation after update
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Cache clear: SSTORE with 0
                    if self.bytecode[j] == 0x60 && j+1 < self.bytecode.len() {  // PUSH1
                        if self.bytecode[j+1] == 0x00 {  // 0
                            for k in j+2..(j+5).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x55 {  // SSTORE (clear)
                                    invalidates_cache = true;
                                }
                            }
                        }
                    }
                }
                
                // Check if this looks like input update (CALLDATALOAD before)
                let mut is_input_update = false;
                for j in (i.saturating_sub(10))..i {
                    if self.bytecode[j] == 0x35 {  // CALLDATALOAD
                        is_input_update = true;
                    }
                }
                
                if is_input_update && !invalidates_cache {
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
                kind: SecurityWarningKind::Brevis,
                severity: v.severity,
                description: format!(
                    "Brevis {:?} at PC {}: {}",
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
    fn test_cache_key_collision() {
        let bytecode = vec![
            0x20, // SHA3
            0x60, 0xFF, // PUSH1 0xFF
            0x16, // AND (truncate)
            0x54, // SLOAD (weak cache key)
        ];
        
        let detector = BrevisDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, BrevisVulnerabilityType::CacheKeyCollision)));
    }

    #[test]
    fn test_cache_bypass() {
        let bytecode = vec![
            0x54, // SLOAD (cache)
            0x15, // ISZERO (check miss)
            0x60, 0x00, // PUSH1 0
            0x52, // MSTORE (use without verify)
        ];
        
        let detector = BrevisDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, BrevisVulnerabilityType::ResultCacheBypass)));
    }
}
