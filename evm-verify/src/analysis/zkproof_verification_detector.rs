/// zkSNARK/zkSTARK Proof Verification Bypass Detector
/// Detects vulnerabilities in zero-knowledge proof verification
/// Critical for: zkRollups, privacy protocols, proof-of-reserves
///
/// Covers: Groth16, PLONK, STARK, pairing checks, public input validation

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKProofVulnerability {
    pub vulnerability_type: ZKProofIssueType,
    pub severity: SecuritySeverity,
    pub confidence: f32,
    pub description: String,
    pub exploit_scenario: String,
    pub location: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ZKProofIssueType {
    UncheckedProofVerification,    // Proof verification result not checked
    PublicInputSubstitution,       // Public inputs not properly validated
    ProofMalleability,             // Same proof valid for different inputs
    PairingCheckBypass,            // Pairing check can be skipped
    MissingNullifierCheck,         // Nullifier not checked (double-spend)
    WeakPublicInputValidation,     // Public inputs not range-checked
    ProofReplay,                   // Proof can be reused
    VerifierKeyMutable,            // Verification key can be changed
    CallbackManipulation,          // Proof callback can be manipulated
}

pub struct ZKProofVerificationDetector {
    bytecode: Vec<u8>,
    pairing_precompiles: HashSet<u8>,
    snark_selectors: HashSet<[u8; 4]>,
}

impl ZKProofVerificationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        let mut pairing_precompiles = HashSet::new();
        pairing_precompiles.insert(0x08); // BN256 pairing precompile

        let mut snark_selectors = HashSet::new();
        snark_selectors.insert([0x8d, 0x72, 0x59, 0x1b]); // verifyProof()
        snark_selectors.insert([0x43, 0x75, 0x3b, 0x4d]); // verify()
        snark_selectors.insert([0x1e, 0x8e, 0x1e, 0x13]); // verifyTx()
        snark_selectors.insert([0xf3, 0x40, 0xfa, 0x01]); // submitProof()
        
        Self {
            bytecode,
            pairing_precompiles,
            snark_selectors,
        }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<ZKProofVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if this is a zkProof contract
        if !self.is_zkproof_contract() {
            return vulnerabilities;
        }

        // Pattern 1: Unchecked proof verification
        vulnerabilities.extend(self.detect_unchecked_verification());

        // Pattern 2: Public input substitution
        vulnerabilities.extend(self.detect_public_input_issues());

        // Pattern 3: Pairing check bypass
        vulnerabilities.extend(self.detect_pairing_bypass());

        // Pattern 4: Proof replay attacks
        vulnerabilities.extend(self.detect_proof_replay());

        // Pattern 5: Nullifier double-spend
        vulnerabilities.extend(self.detect_missing_nullifier());

        vulnerabilities
    }

    fn detect_unchecked_verification(&self) -> Vec<ZKProofVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: STATICCALL to pairing precompile without ISZERO check
        for i in 0..self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0xFA { // STATICCALL
                // Check if calling pairing precompile (address 0x08)
                let is_pairing_call = self.is_pairing_precompile_call(i);
                
                if is_pairing_call {
                    // Check if return value is validated
                    let has_return_check = self.has_return_value_check(i);
                    
                    if !has_return_check {
                        vulnerabilities.push(ZKProofVulnerability {
                            vulnerability_type: ZKProofIssueType::UncheckedProofVerification,
                            severity: SecuritySeverity::Critical,
                            confidence: 0.90,
                            description: "Pairing check result not validated - proof verification bypassed".to_string(),
                            exploit_scenario: format!(
                                "Exploit at position {}:\n\
                                1. Attacker submits invalid proof\n\
                                2. Pairing check fails but result not checked\n\
                                3. Contract proceeds as if proof valid\n\
                                4. Complete bypass of zkProof security\n\n\
                                Fix: require(pairingCheck(...), 'Invalid proof')",
                                i
                            ),
                            location: i,
                        });
                    }
                }
            }

            // Check for verifyProof() calls without result check
            for selector in &self.snark_selectors {
                if i + 4 <= self.bytecode.len() && &self.bytecode[i..i+4] == selector {
                    if !self.has_return_value_check(i + 10) {
                        vulnerabilities.push(ZKProofVulnerability {
                            vulnerability_type: ZKProofIssueType::UncheckedProofVerification,
                            severity: SecuritySeverity::Critical,
                            confidence: 0.85,
                            description: "verifyProof() return value not checked".to_string(),
                            exploit_scenario: format!(
                                "Exploit at position {}:\n\
                                1. verifyProof() called but result ignored\n\
                                2. Proof verification may fail silently\n\
                                3. Attacker can submit any proof\n\
                                4. zkSecurity completely bypassed\n\n\
                                Fix: bool valid = verifyProof(...); require(valid)",
                                i
                            ),
                            location: i,
                        });
                    }
                }
            }
        }

        vulnerabilities
    }

    fn detect_public_input_issues(&self) -> Vec<ZKProofVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: CALLDATALOAD for public inputs without validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.is_in_proof_verification_context(i) {
                // Look for CALLDATALOAD without subsequent bounds check
                if self.bytecode[i] == 0x35 { // CALLDATALOAD
                    let has_bounds_check = self.has_bounds_check_after(i);
                    
                    if !has_bounds_check {
                        vulnerabilities.push(ZKProofVulnerability {
                            vulnerability_type: ZKProofIssueType::WeakPublicInputValidation,
                            severity: SecuritySeverity::High,
                            confidence: 0.75,
                            description: "Public inputs not range-checked before proof verification".to_string(),
                            exploit_scenario: format!(
                                "Exploit at position {}:\n\
                                1. Attacker provides out-of-range public inputs\n\
                                2. May cause proof verification to pass unexpectedly\n\
                                3. Or exploit arithmetic overflow in verification\n\
                                4. Proof valid for different semantic meaning\n\n\
                                Fix: require(publicInput < FIELD_SIZE)",
                                i
                            ),
                            location: i,
                        });
                    }
                }

                // Check for public input substitution vulnerability
                if self.has_public_input_storage_conflict(i) {
                    vulnerabilities.push(ZKProofVulnerability {
                        vulnerability_type: ZKProofIssueType::PublicInputSubstitution,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.80,
                        description: "Public inputs can be substituted after proof generation".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. User generates proof with publicInput A\n\
                            2. Attacker front-runs and changes stored publicInput to B\n\
                            3. Proof verification uses B instead of A\n\
                            4. Proof proves something different than intended\n\n\
                            Fix: Include publicInput in proof, don't load from storage",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_pairing_bypass(&self) -> Vec<ZKProofVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Conditional STATICCALL to pairing that can be skipped
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x57 || self.bytecode[i] == 0x58 { // JUMPI or PC
                // Check if this controls pairing check execution
                let controls_pairing = self.controls_pairing_execution(i);
                
                if controls_pairing {
                    vulnerabilities.push(ZKProofVulnerability {
                        vulnerability_type: ZKProofIssueType::PairingCheckBypass,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.70,
                        description: "Pairing check can be skipped via conditional logic".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. Control flow allows skipping pairing check\n\
                            2. Attacker manipulates conditions to avoid verification\n\
                            3. Invalid proofs accepted\n\
                            4. zkProof security completely bypassed\n\n\
                            Fix: Ensure pairing check always executes unconditionally",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_proof_replay(&self) -> Vec<ZKProofVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Pattern: Proof verification without nonce or unique identifier
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.is_in_proof_verification_context(i) {
                // Check if proof has unique identifier (nonce, nullifier, or commitment)
                let has_unique_id = self.has_proof_uniqueness_check(i);
                
                if !has_unique_id {
                    vulnerabilities.push(ZKProofVulnerability {
                        vulnerability_type: ZKProofIssueType::ProofReplay,
                        severity: SecuritySeverity::High,
                        confidence: 0.75,
                        description: "Proof can be replayed - no uniqueness enforcement".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. User submits valid proof for transaction A\n\
                            2. Attacker captures and replays same proof\n\
                            3. Same proof accepted multiple times\n\
                            4. Double-spend or repeated action\n\n\
                            Fix: Include nonce/nullifier in public inputs, mark as used",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_missing_nullifier(&self) -> Vec<ZKProofVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check if this appears to be a privacy protocol (has KECCAK256 + proof verification)
        let is_privacy_protocol = self.has_privacy_pattern();
        
        if !is_privacy_protocol {
            return vulnerabilities;
        }

        // Pattern: No nullifier storage/checking for private transactions
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.is_in_proof_verification_context(i) {
                // Look for nullifier SLOAD check pattern
                let has_nullifier_check = self.has_nullifier_pattern(i);
                
                if !has_nullifier_check {
                    vulnerabilities.push(ZKProofVulnerability {
                        vulnerability_type: ZKProofIssueType::MissingNullifierCheck,
                        severity: SecuritySeverity::Critical,
                        confidence: 0.80,
                        description: "Privacy protocol missing nullifier double-spend check".to_string(),
                        exploit_scenario: format!(
                            "Exploit at position {}:\n\
                            1. User spends note with nullifier N\n\
                            2. Attacker replays same proof with nullifier N\n\
                            3. No check if nullifier already used\n\
                            4. Double-spend of private funds\n\n\
                            Fix: require(!nullifierUsed[nullifier]); nullifierUsed[nullifier] = true",
                            i
                        ),
                        location: i,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn is_zkproof_contract(&self) -> bool {
        // Check for pairing precompile calls or proof verification selectors
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xFA { // STATICCALL
                if self.is_pairing_precompile_call(i) {
                    return true;
                }
            }
        }
        
        // Check for proof verification function selectors
        for selector in &self.snark_selectors {
            if self.bytecode.windows(4).any(|w| w == *selector) {
                return true;
            }
        }
        
        false
    }

    fn is_pairing_precompile_call(&self, pos: usize) -> bool {
        // Look back for PUSH1 0x08 (pairing precompile address)
        for i in pos.saturating_sub(20)..pos {
            if self.bytecode[i] == 0x60 && // PUSH1
               i + 1 < self.bytecode.len() &&
               self.bytecode[i + 1] == 0x08 {
                return true;
            }
        }
        false
    }

    fn has_return_value_check(&self, pos: usize) -> bool {
        // Look for ISZERO or DUP + PUSH + JUMPI pattern (checking return value)
        for i in pos..pos.saturating_add(15).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x15 || // ISZERO
               (self.bytecode[i] == 0x80 && // DUP1
                i + 2 < self.bytecode.len() &&
                self.bytecode[i + 2] == 0x57) { // JUMPI
                return true;
            }
        }
        false
    }

    fn has_bounds_check_after(&self, pos: usize) -> bool {
        // Look for LT, GT, or EQ comparison after CALLDATALOAD
        for i in pos..pos.saturating_add(10).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x10 || // LT
               self.bytecode[i] == 0x11 || // GT
               self.bytecode[i] == 0x14 { // EQ
                return true;
            }
        }
        false
    }

    fn is_in_proof_verification_context(&self, pos: usize) -> bool {
        // Check if position is near proof verification selector or pairing call
        for i in pos.saturating_sub(100)..pos.saturating_add(100).min(self.bytecode.len()) {
            if i + 4 <= self.bytecode.len() {
                for selector in &self.snark_selectors {
                    if &self.bytecode[i..i+4] == selector {
                        return true;
                    }
                }
            }
            if self.bytecode[i] == 0xFA && self.is_pairing_precompile_call(i) {
                return true;
            }
        }
        false
    }

    fn has_public_input_storage_conflict(&self, pos: usize) -> bool {
        // Look for SLOAD near CALLDATALOAD in proof context (risky pattern)
        for i in pos..pos.saturating_add(20).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x54 { // SLOAD after CALLDATALOAD
                return true;
            }
        }
        false
    }

    fn controls_pairing_execution(&self, pos: usize) -> bool {
        // Check if JUMPI targets skip over pairing call
        for i in pos..pos.saturating_add(50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0xFA && self.is_pairing_precompile_call(i) {
                return true;
            }
        }
        false
    }

    fn has_proof_uniqueness_check(&self, pos: usize) -> bool {
        // Look for SLOAD/SSTORE pattern that marks proof as used
        let mut has_sload = false;
        let mut has_sstore = false;
        
        for i in pos..pos.saturating_add(100).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x54 { has_sload = true; }
            if self.bytecode[i] == 0x55 { has_sstore = true; }
        }
        
        has_sload && has_sstore
    }

    fn has_privacy_pattern(&self) -> bool {
        // Privacy protocols have commitment/nullifier patterns (KECCAK256 + proof)
        let has_hash = self.bytecode.iter().any(|&b| b == 0x20); // KECCAK256
        let has_proof = self.is_zkproof_contract();
        has_hash && has_proof
    }

    fn has_nullifier_pattern(&self, pos: usize) -> bool {
        // Look for mapping[nullifier] check: SLOAD, ISZERO, REQUIRE pattern
        for i in pos..pos.saturating_add(50).min(self.bytecode.len()) {
            if self.bytecode[i] == 0x54 && // SLOAD (nullifierUsed)
               i + 2 < self.bytecode.len() &&
               self.bytecode[i + 1] == 0x15 && // ISZERO
               i + 10 < self.bytecode.len() {
                // Look for subsequent SSTORE (marking nullifier used)
                for j in i..i + 30 {
                    if j < self.bytecode.len() && self.bytecode[j] == 0x55 {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unchecked_pairing() {
        let bytecode = vec![
            0x60, 0x08, // PUSH1 0x08 (pairing precompile)
            0xFA, // STATICCALL
            // Missing return value check
            0x55, // SSTORE (proceed without checking)
        ];
        
        let detector = ZKProofVerificationDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, ZKProofIssueType::UncheckedProofVerification)));
    }

    #[test]
    fn test_public_input_no_validation() {
        let bytecode = vec![
            0x8d, 0x72, 0x59, 0x1b, // verifyProof selector
            0x35, // CALLDATALOAD (public input)
            // No bounds check
            0xFA, // STATICCALL (verification)
        ];
        
        let detector = ZKProofVerificationDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, ZKProofIssueType::WeakPublicInputValidation)));
    }
}
