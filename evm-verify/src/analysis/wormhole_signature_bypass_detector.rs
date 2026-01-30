use serde::{Serialize, Deserialize};

/// Wormhole Signature Verification Bypass Detection ($325M February 2022)
/// 
/// The Wormhole hack exploited a vulnerability where:
/// 1. Guardian signatures were required to validate cross-chain messages
/// 2. The verification function used `load_current()` for sysvar account
/// 3. Attacker spoofed the sysvar account data without proper initialization check
/// 4. This allowed forging guardian signatures without actual private keys
/// 5. The bridge accepted the fake signatures and minted tokens
///
/// Key patterns (adapted for EVM):
/// - Multi-signature verification without proper signer validation
/// - Guardian/validator sets loaded from storage without integrity checks
/// - Signature verification that doesn't validate signer authority
/// - Missing checks for initialized/authentic validator sets

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WormholeSignatureVulnerability {
    /// Critical: Signature verification accepts unvalidated signer set
    UninitializedSignerSet {
        description: String,
        location: usize,
        confidence: f32,
    },
    
    /// Critical: Guardian signatures verified without authority check
    MissingSignerAuthorityValidation {
        description: String,
        location: usize,
        confidence: f32,
    },
    
    /// High: Multi-sig threshold can be bypassed through signer manipulation
    SignerSetManipulation {
        description: String,
        location: usize,
        confidence: f32,
    },
    
    /// High: Signature aggregation without individual signer verification
    WeakSignatureAggregation {
        description: String,
        location: usize,
        confidence: f32,
    },
}

pub struct WormholeSignatureBypassDetector {
    bytecode: Vec<u8>,
}

impl WormholeSignatureBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<WormholeSignatureVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Uninitialized guardian/signer set
        vulnerabilities.extend(self.detect_uninitialized_signer_set());
        
        // Pattern 2: Missing signer authority validation
        vulnerabilities.extend(self.detect_missing_authority_check());
        
        // Pattern 3: Signer set manipulation
        vulnerabilities.extend(self.detect_signer_set_manipulation());
        
        // Pattern 4: Weak signature aggregation
        vulnerabilities.extend(self.detect_weak_signature_aggregation());
        
        vulnerabilities
    }
    
    fn detect_uninitialized_signer_set(&self) -> Vec<WormholeSignatureVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Look for ecrecover or signature verification patterns
        let ecrecover_sig = &[0x00, 0x00, 0x00, 0x01]; // ecrecover precompile address
        
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if i + 100 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 100];
                
                // Look for STATICCALL to ecrecover
                let has_ecrecover = section.windows(4).any(|w| w == ecrecover_sig);
                let has_staticcall = section.contains(&0xFA); // STATICCALL
                
                if has_ecrecover && has_staticcall {
                    // Check if recovered address is compared to stored guardian set
                    let has_sload = section.contains(&0x54); // SLOAD (guardian set)
                    let has_comparison = section.contains(&0x14); // EQ
                    
                    if has_sload && has_comparison {
                        // Check for initialization validation of guardian set
                        let has_init_check = section.windows(5).any(|w| {
                            // Pattern: SLOAD → ISZERO → JUMPI (revert if not initialized)
                            w[0] == 0x54 && w[1] == 0x15 && w[2] == 0x57
                        });
                        
                        if !has_init_check {
                            vulnerabilities.push(WormholeSignatureVulnerability::UninitializedSignerSet {
                                description: format!(
                                    "Signature verification at PC {} loads guardian/signer set without initialization check. \
                                    This is the EXACT Wormhole exploit pattern ($325M). \
                                    Attacker can provide fake guardian set data and forge signatures.",
                                    i
                                ),
                                location: i,
                                confidence: 0.94,
                            });
                        }
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn detect_missing_authority_check(&self) -> Vec<WormholeSignatureVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Look for signature verification functions
        let verify_sigs = [
            &[0x1f, 0x7e, 0xc0, 0xa8][..], // verifySignatures() or similar
            &[0x72, 0x4a, 0x7d, 0x8c][..], // verify()
        ];
        
        for sig in &verify_sigs {
            for i in 0..self.bytecode.len().saturating_sub(4) {
                if &self.bytecode[i..i + 4] == *sig {
                    let func_section = &self.bytecode[i..std::cmp::min(i + 300, self.bytecode.len())];
                    
                    // Check for ecrecover usage
                    let has_signature_recovery = func_section.contains(&0xFA) && // STATICCALL
                        func_section.windows(4).any(|w| w == &[0x00, 0x00, 0x00, 0x01]);
                    
                    // Check for authority validation (comparing against authorized set)
                    let has_authority_check = func_section.windows(10).any(|w| {
                        // Pattern: recovered address → SLOAD authorized list → comparison → require
                        w.contains(&0x54) && // SLOAD
                        w.contains(&0x14) && // EQ  
                        w.contains(&0x15) && // ISZERO (negate)
                        w.contains(&0xFD)    // REVERT if not authorized
                    });
                    
                    if has_signature_recovery && !has_authority_check {
                        vulnerabilities.push(WormholeSignatureVulnerability::MissingSignerAuthorityValidation {
                            description: format!(
                                "Signature verification at PC {} recovers signer but doesn't validate \
                                they're an authorized guardian. Wormhole was exploited by providing \
                                signatures from arbitrary addresses that weren't actual guardians.",
                                i
                            ),
                            location: i,
                            confidence: 0.91,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn detect_signer_set_manipulation(&self) -> Vec<WormholeSignatureVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Look for functions that update guardian/signer sets
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if i + 150 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 150];
                
                // Look for storage write to guardian set
                let has_guardian_update = section.contains(&0x55); // SSTORE
                
                // Check for loop patterns (updating multiple guardians)
                let has_loop = section.contains(&0x57); // JUMPI
                
                if has_guardian_update && has_loop {
                    // Check for proper access control
                    let has_owner_check = section.windows(15).any(|w| {
                        // Pattern: CALLER → compare with owner → require
                        w.contains(&0x33) && // CALLER
                        w.contains(&0x54) && // SLOAD (owner)
                        w.contains(&0x14) && // EQ
                        w.contains(&0xFD)    // REVERT if not owner
                    });
                    
                    // Check for minimum guardian threshold enforcement
                    let has_threshold_check = section.windows(10).any(|w| {
                        // Pattern: count > MIN_GUARDIANS
                        w.contains(&0x10) || w.contains(&0x12) // LT or SLT
                    });
                    
                    if !has_owner_check || !has_threshold_check {
                        vulnerabilities.push(WormholeSignatureVulnerability::SignerSetManipulation {
                            description: format!(
                                "Guardian/signer set update at PC {} lacks proper protection. \
                                Can be manipulated to reduce security threshold or add unauthorized signers. \
                                Should require: (1) strong access control, (2) minimum guardian count, \
                                (3) timelock for changes.",
                                i
                            ),
                            location: i,
                            confidence: 0.87,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn detect_weak_signature_aggregation(&self) -> Vec<WormholeSignatureVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Look for signature aggregation/batching patterns
        for i in 0..self.bytecode.len().saturating_sub(200) {
            if i + 200 < self.bytecode.len() {
                let section = &self.bytecode[i..i + 200];
                
                // Look for loop with signature verification
                let has_loop = section.contains(&0x57); // JUMPI
                let has_sig_verify = section.contains(&0xFA) && // STATICCALL
                    section.windows(4).any(|w| w == &[0x00, 0x00, 0x00, 0x01]); // ecrecover
                
                if has_loop && has_sig_verify {
                    // Check for per-signature validation (not just count)
                    let validates_each_sig = section.windows(20).any(|w| {
                        // Pattern: recovered address stored → checked individually
                        w.contains(&0x55) && // SSTORE (store recovered)
                        w.contains(&0x54) && // SLOAD (load for check)
                        w.contains(&0x15)    // ISZERO (validation)
                    });
                    
                    // Check for duplicate signature prevention
                    let prevents_duplicates = section.windows(15).any(|w| {
                        // Pattern: check if signer already seen
                        w.contains(&0x54) && // SLOAD (check bitmap/set)
                        w.contains(&0x17) && // OR (set bit)
                        w.contains(&0x55)    // SSTORE (update bitmap)
                    });
                    
                    if !validates_each_sig || !prevents_duplicates {
                        vulnerabilities.push(WormholeSignatureVulnerability::WeakSignatureAggregation {
                            description: format!(
                                "Signature aggregation at PC {} doesn't properly validate each signer. \
                                Missing: (1) individual signer authority check, (2) duplicate prevention. \
                                Attacker could submit same signature multiple times or mix valid/invalid.",
                                i
                            ),
                            location: i,
                            confidence: 0.84,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_wormhole_vulnerable_pattern() {
        // Simulate vulnerable pattern:
        // ecrecover → SLOAD guardian → EQ (no initialization check)
        let bytecode = vec![
            0x60, 0x01, // PUSH1 1 (ecrecover)
            0xFA, // STATICCALL
            0x54, // SLOAD (guardian set)
            0x14, // EQ (compare)
            // Missing: ISZERO check for guardian set initialization
        ];
        
        let detector = WormholeSignatureBypassDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(!vulns.is_empty(), "Should detect Wormhole-style vulnerability");
    }
    
    #[test]
    fn test_safe_guardian_validation() {
        // Simulate safe pattern with initialization and authority check
        let bytecode = vec![
            0x54, // SLOAD (guardian set)
            0x15, // ISZERO (check if initialized)
            0x60, 0x00, // PUSH1 0
            0x57, // JUMPI (revert if not initialized)
            0xFD, // REVERT
            0x60, 0x01, // PUSH1 1 (ecrecover)
            0xFA, // STATICCALL
            0x54, // SLOAD (check if recovered address is guardian)
            0x14, // EQ
            0x15, // ISZERO (negate)
            0xFD, // REVERT if not guardian
        ];
        
        let detector = WormholeSignatureBypassDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        // Should have no or fewer critical vulnerabilities
        let critical = vulns.iter().filter(|v| matches!(v,
            WormholeSignatureVulnerability::UninitializedSignerSet { confidence, .. } if *confidence > 0.9
        )).count();
        
        assert_eq!(critical, 0, "Should not flag safe initialization pattern");
    }
}
