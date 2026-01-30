// Axiom Historical Block Proof Manipulation Detector
// Detects manipulation in ZK-proven historical Ethereum data queries

use crate::bytecode::security::{SecuritySeverity, SecurityWarning, SecurityWarningKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxiomVulnerability {
    pub location: usize,
    pub vulnerability_type: AxiomVulnerabilityType,
    pub severity: SecuritySeverity,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AxiomVulnerabilityType {
    BlockHeaderForging,             // Forge historical block headers
    ProofVerificationBypass,        // Bypass ZK proof verification
    QueryResultCachePoisoning,      // Poison cached query results
    BlockRangeManipulation,         // Manipulate query block range
    MerkleProofIncomplete,          // Incomplete Merkle proof verification
    StateRootMismatch,              // State root not validated
}

pub struct AxiomDetector {
    bytecode: Vec<u8>,
}

impl AxiomDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<AxiomVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_header_forging() {
            vulnerabilities.push(AxiomVulnerability {
                location: loc,
                vulnerability_type: AxiomVulnerabilityType::BlockHeaderForging,
                severity: SecuritySeverity::Critical,
                description: "Block header not verified against consensus layer. Attacker can submit \
                             forged historical headers to manipulate query results.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_proof_bypass() {
            vulnerabilities.push(AxiomVulnerability {
                location: loc,
                vulnerability_type: AxiomVulnerabilityType::ProofVerificationBypass,
                severity: SecuritySeverity::Critical,
                description: "ZK proof verification result not checked. Failed proof still allows \
                             query result to be accepted and used onchain.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_cache_poisoning() {
            vulnerabilities.push(AxiomVulnerability {
                location: loc,
                vulnerability_type: AxiomVulnerabilityType::QueryResultCachePoisoning,
                severity: SecuritySeverity::High,
                description: "Query result cache uses weak key. Attacker can poison cache with \
                             incorrect results affecting subsequent queries.".to_string(),
                confidence: 0.82,
            });
        }

        if let Some(loc) = self.detect_range_manipulation() {
            vulnerabilities.push(AxiomVulnerability {
                location: loc,
                vulnerability_type: AxiomVulnerabilityType::BlockRangeManipulation,
                severity: SecuritySeverity::High,
                description: "Block range not validated. Query can specify invalid range causing \
                             incorrect aggregation or bypassing limits.".to_string(),
                confidence: 0.84,
            });
        }

        if let Some(loc) = self.detect_merkle_incomplete() {
            vulnerabilities.push(AxiomVulnerability {
                location: loc,
                vulnerability_type: AxiomVulnerabilityType::MerkleProofIncomplete,
                severity: SecuritySeverity::High,
                description: "Merkle proof verification incomplete. Missing sibling validation \
                             allows forged proofs to pass verification.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_stateroot_mismatch() {
            vulnerabilities.push(AxiomVulnerability {
                location: loc,
                vulnerability_type: AxiomVulnerabilityType::StateRootMismatch,
                severity: SecuritySeverity::Critical,
                description: "State root not validated against block header. Query result can claim \
                             state from wrong block.".to_string(),
                confidence: 0.88,
            });
        }

        vulnerabilities
    }

    fn detect_header_forging(&self) -> Option<usize> {
        // Pattern: Block header accepted without consensus verification
        // CALLDATALOAD (header) → use without STATICCALL (verify consensus)
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (block header)
                let mut verified_consensus = false;
                
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xFA {  // STATICCALL (consensus verification)
                        verified_consensus = true;
                    }
                    
                    // Header hash stored without verification
                    if !verified_consensus && self.bytecode[j] == 0x55 {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_proof_bypass(&self) -> Option<usize> {
        // Pattern: ZK proof verification result ignored
        // STATICCALL (verify ZK proof) → result not checked
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xFA {  // STATICCALL (verify proof)
                let mut checks_result = false;
                
                for j in i+1..(i+15).min(self.bytecode.len()) {
                    // Result check: ISZERO → REVERT on failure
                    if self.bytecode[j] == 0x15 {  // ISZERO
                        for k in j+1..(j+3).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0xFD {  // REVERT
                                checks_result = true;
                            }
                        }
                    }
                    
                    // Result popped (ignored)
                    if self.bytecode[j] == 0x50 && !checks_result {  // POP
                        return Some(i);
                    }
                }
                
                if !checks_result {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_cache_poisoning(&self) -> Option<usize> {
        // Pattern: Cache key without cryptographic binding
        // Storage key for cache without SHA3 of all query params
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x54 {  // SLOAD (cache lookup)
                let mut uses_strong_key = false;
                
                // Check if key uses cryptographic hash
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x20 {  // SHA3
                        // Check if multiple params hashed
                        let push_count = (j.saturating_sub(10)..j)
                            .filter(|&k| matches!(self.bytecode[k], 0x60..=0x7F) || self.bytecode[k] == 0x35)
                            .count();
                        if push_count >= 3 {  // blockNum + query type + params
                            uses_strong_key = true;
                        }
                    }
                }
                
                // Cache used with weak key
                if !uses_strong_key {
                    for j in i+1..(i+15).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x15 {  // ISZERO (cache miss check)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_range_manipulation(&self) -> Option<usize> {
        // Pattern: Block range used without validation
        // startBlock/endBlock without bounds check
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (block number)
                let mut validates_range = false;
                
                // Check for range validation (diff < max, both > 0)
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    // Range check: SUB followed by LT
                    if self.bytecode[j] == 0x03 {  // SUB (end - start)
                        for k in j+1..(j+5).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 {  // LT (< max range)
                                validates_range = true;
                            }
                        }
                    }
                }
                
                // Block number used in loop without validation
                if !validates_range {
                    for j in i+1..(i+15).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x5B {  // JUMPDEST (loop over range)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_merkle_incomplete(&self) -> Option<usize> {
        // Pattern: Merkle proof verification without sibling validation
        // Single SHA3 without iterating over proof siblings
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x20 {  // SHA3 (hash leaf/node)
                let mut has_loop = false;
                let mut validates_siblings = false;
                
                // Check if in loop (iterating siblings)
                for j in (i.saturating_sub(15))..i {
                    if self.bytecode[j] == 0x5B {  // JUMPDEST
                        has_loop = true;
                    }
                }
                
                // Check for sibling validation
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // Multiple hashes (climbing tree)
                    if self.bytecode[j] == 0x20 && has_loop {
                        validates_siblings = true;
                    }
                }
                
                // Single hash without iteration
                if !has_loop || !validates_siblings {
                    for j in i+1..(i+20).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x14 {  // EQ (check root)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_stateroot_mismatch(&self) -> Option<usize> {
        // Pattern: State query without state root validation
        // Query result without comparing against block.stateRoot
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x35 {  // CALLDATALOAD (query result)
                let mut validates_stateroot = false;
                
                // Check for state root validation
                for j in i+1..(i+25).min(self.bytecode.len()) {
                    // State root comparison
                    if self.bytecode[j] == 0x20 {  // SHA3 (merkle root)
                        for k in j+1..(j+8).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x14 {  // EQ (compare against expected)
                                validates_stateroot = true;
                            }
                        }
                    }
                }
                
                // Result stored without state root check
                if !validates_stateroot {
                    for j in i+1..(i+20).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 {
                            return Some(i);
                        }
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
                kind: SecurityWarningKind::Axiom,
                severity: v.severity,
                description: format!(
                    "Axiom {:?} at PC {}: {}",
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
    fn test_header_forging() {
        let bytecode = vec![
            0x35, // CALLDATALOAD (block header)
            0x60, 0x00, // PUSH1 0
            0x55, // SSTORE (no consensus verification)
        ];
        
        let detector = AxiomDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, AxiomVulnerabilityType::BlockHeaderForging)));
    }

    #[test]
    fn test_proof_bypass() {
        let bytecode = vec![
            0xFA, // STATICCALL (verify proof)
            0x50, // POP (ignore result)
        ];
        
        let detector = AxiomDetector::new(bytecode);
        let vulns = detector.detect();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, AxiomVulnerabilityType::ProofVerificationBypass)));
    }
}
