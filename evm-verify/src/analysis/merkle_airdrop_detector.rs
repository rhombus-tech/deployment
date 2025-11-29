// Merkle Tree / Airdrop Vulnerability Detector
// Detects vulnerabilities in merkle proof verification and airdrop claim mechanisms
// Historical: Multiple airdrop exploits, double-claim attacks, merkle manipulation

use crate::bytecode::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleAirdropVulnerability {
    pub vulnerability_type: MerkleAirdropType,
    pub severity: SecuritySeverity,
    pub location: usize,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MerkleAirdropType {
    DoubleClaim,                  // No protection against claiming twice
    MerkleProofNotVerified,       // Proof verification missing or weak
    MaliciousMerkleRoot,          // Root can be changed by admin
    ClaimFrontRunning,            // Claims vulnerable to front-running
    MissingClaimTracking,         // No mapping to track claimed addresses
    WeakProofVerification,        // Proof verification logic flawed
    UnlimitedClaims,              // Same address can claim multiple times
    MerkleRootImmutability,       // Root should be immutable but isn't
    ClaimWithoutProof,            // Claim function doesn't require proof
    InvalidLeafHashing,           // Leaf hash computed incorrectly
    ProofReplay,                  // Proof can be replayed for different amounts
    MissingNonceOrTimestamp,      // No time/nonce protection on claims
}

pub struct MerkleAirdropDetector {
    bytecode: Vec<u8>,
}

impl MerkleAirdropDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<MerkleAirdropVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Only analyze if this looks like an airdrop/claim contract
        if !self.detect_airdrop_pattern() {
            return vulnerabilities;
        }

        vulnerabilities.extend(self.detect_double_claim());
        vulnerabilities.extend(self.detect_weak_proof_verification());
        vulnerabilities.extend(self.detect_mutable_root());
        vulnerabilities.extend(self.detect_claim_without_proof());
        vulnerabilities.extend(self.detect_missing_claim_tracking());

        vulnerabilities
    }

    fn detect_airdrop_pattern(&self) -> bool {
        // Look for "claim" function signature or merkle-related patterns
        let claim_sigs = [
            &[0x4e, 0x71, 0xd9, 0x2d][..], // claim()
            &[0x2e, 0x7b, 0xa6, 0xef][..], // claim(uint256,bytes32[])
        ];

        let has_claim = claim_sigs.iter().any(|sig| {
            self.bytecode.windows(sig.len()).any(|w| w == *sig)
        });

        // Look for keccak256 usage (used in merkle proof verification)
        let has_hash = self.bytecode.contains(&0x20); // SHA3

        has_claim || has_hash
    }

    fn detect_double_claim(&self) -> Vec<MerkleAirdropVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for claim function
        let claim_sig = &[0x4e, 0x71, 0xd9, 0x2d][..]; // claim()
        
        if let Some(pos) = self.bytecode.windows(claim_sig.len()).position(|w| w == claim_sig) {
            // Check if there's a mapping check (SLOAD followed by ISZERO/EQ for claimed flag)
            let function_section = &self.bytecode[pos..pos.saturating_add(100).min(self.bytecode.len())];
            
            // Look for pattern: SLOAD -> ISZERO -> JUMPI (checking if already claimed)
            let has_claim_check = function_section.windows(3).any(|w| {
                w[0] == 0x54 && // SLOAD
                w[1] == 0x15 && // ISZERO
                w[2] == 0x57    // JUMPI
            });

            if !has_claim_check {
                vulnerabilities.push(MerkleAirdropVulnerability {
                    vulnerability_type: MerkleAirdropType::DoubleClaim,
                    severity: SecuritySeverity::Critical,
                    location: pos,
                    description: "Claim function has no protection against double claims".to_string(),
                    exploit_scenario: "Attacker can claim airdrop multiple times, draining the contract".to_string(),
                    remediation: "Add mapping(address => bool) claimed; require(!claimed[msg.sender]); claimed[msg.sender] = true;".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_weak_proof_verification(&self) -> Vec<MerkleAirdropVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for merkle proof verification patterns
        // Should have: loop with keccak256(abi.encodePacked(current, proof[i]))
        let has_keccak = self.bytecode.contains(&0x20); // SHA3
        let has_loop = self.bytecode.windows(2).any(|w| {
            w[0] == 0x5b && // JUMPDEST
            w[1] == 0x57    // JUMPI (loop condition)
        });

        if has_keccak && !has_loop {
            vulnerabilities.push(MerkleAirdropVulnerability {
                vulnerability_type: MerkleAirdropType::WeakProofVerification,
                severity: SecuritySeverity::High,
                location: 0,
                description: "Merkle proof verification appears weak or incomplete".to_string(),
                exploit_scenario: "Attacker can forge proofs or claim amounts not allocated to them".to_string(),
                remediation: "Use standard OpenZeppelin MerkleProof library for verification".to_string(),
            });
        }

        // Check if proof is actually used in verification
        if has_keccak {
            // Look for CALLDATALOAD (reading proof from calldata)
            let uses_calldata = self.bytecode.contains(&0x35); // CALLDATALOAD
            
            if !uses_calldata {
                vulnerabilities.push(MerkleAirdropVulnerability {
                    vulnerability_type: MerkleAirdropType::ClaimWithoutProof,
                    severity: SecuritySeverity::Critical,
                    location: 0,
                    description: "Claim function may not require merkle proof".to_string(),
                    exploit_scenario: "Anyone can claim without providing valid proof".to_string(),
                    remediation: "Require merkle proof parameter and verify it against stored root".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_mutable_root(&self) -> Vec<MerkleAirdropVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for function that can change merkle root
        // Pattern: CALLER check followed by SSTORE to root storage slot
        let mut i = 0;
        while i < self.bytecode.len().saturating_sub(20) {
            if self.bytecode[i] == 0x33 { // CALLER (access control check)
                let section = &self.bytecode[i..i+20.min(self.bytecode.len()-i)];
                
                // Check if this leads to SSTORE (updating storage)
                if section.contains(&0x55) {
                    vulnerabilities.push(MerkleAirdropVulnerability {
                        vulnerability_type: MerkleAirdropType::MaliciousMerkleRoot,
                        severity: SecuritySeverity::High,
                        location: i,
                        description: "Merkle root can be changed by admin after deployment".to_string(),
                        exploit_scenario: "Malicious admin can change root to allocate tokens to themselves".to_string(),
                        remediation: "Make merkle root immutable after initial setup, or use timelock/governance for changes".to_string(),
                    });
                    break;
                }
            }
            i += 1;
        }

        vulnerabilities
    }

    fn detect_claim_without_proof(&self) -> Vec<MerkleAirdropVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for token transfer (CALL or TRANSFER) without prior merkle verification
        let claim_sig = &[0x4e, 0x71, 0xd9, 0x2d][..]; // claim()
        
        if let Some(pos) = self.bytecode.windows(claim_sig.len()).position(|w| w == claim_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(50).min(self.bytecode.len())];
            
            // Check for CALL (transfer) without SHA3 (merkle verification) before it
            let has_transfer = function_section.contains(&0xf1) || // CALL
                              function_section.contains(&0xa9); // transfer function sig
            let has_verification = function_section.contains(&0x20); // SHA3

            if has_transfer && !has_verification {
                vulnerabilities.push(MerkleAirdropVulnerability {
                    vulnerability_type: MerkleAirdropType::ClaimWithoutProof,
                    severity: SecuritySeverity::Critical,
                    location: pos,
                    description: "Token transfer occurs without merkle proof verification".to_string(),
                    exploit_scenario: "Anyone can claim tokens without valid proof".to_string(),
                    remediation: "Verify merkle proof before transferring tokens".to_string(),
                });
            }
        }

        vulnerabilities
    }

    fn detect_missing_claim_tracking(&self) -> Vec<MerkleAirdropVulnerability> {
        let mut vulnerabilities = Vec::new();

        let claim_sig = &[0x4e, 0x71, 0xd9, 0x2d][..]; // claim()
        
        if let Some(pos) = self.bytecode.windows(claim_sig.len()).position(|w| w == claim_sig) {
            let function_section = &self.bytecode[pos..pos.saturating_add(100).min(self.bytecode.len())];
            
            // Check for SSTORE after claim (marking as claimed)
            // Should have: load claimed[msg.sender], check it's false, then set to true
            let loads = function_section.iter().filter(|&&b| b == 0x54).count(); // SLOAD
            let stores = function_section.iter().filter(|&&b| b == 0x55).count(); // SSTORE
            
            if stores == 0 {
                vulnerabilities.push(MerkleAirdropVulnerability {
                    vulnerability_type: MerkleAirdropType::MissingClaimTracking,
                    severity: SecuritySeverity::Critical,
                    location: pos,
                    description: "No storage update to track claimed addresses".to_string(),
                    exploit_scenario: "Same address can claim unlimited times".to_string(),
                    remediation: "Store claimed status: mapping(address => bool) public claimed; claimed[msg.sender] = true;".to_string(),
                });
            } else if loads == 0 && stores > 0 {
                vulnerabilities.push(MerkleAirdropVulnerability {
                    vulnerability_type: MerkleAirdropType::UnlimitedClaims,
                    severity: SecuritySeverity::Critical,
                    location: pos,
                    description: "Claim status stored but never checked".to_string(),
                    exploit_scenario: "Storage write without read check allows unlimited claims".to_string(),
                    remediation: "Check claimed status before processing: require(!claimed[msg.sender])".to_string(),
                });
            }
        }

        vulnerabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_double_claim() {
        // Claim function without SLOAD check
        let mut bytecode = vec![0x00; 50];
        bytecode[10..14].copy_from_slice(&[0x4e, 0x71, 0xd9, 0x2d]); // claim()
        bytecode[20] = 0xf1; // CALL (transfer)
        // No SLOAD/ISZERO/JUMPI pattern
        
        let detector = MerkleAirdropDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, MerkleAirdropType::DoubleClaim)));
    }

    #[test]
    fn test_detect_claim_without_proof() {
        // Claim with transfer but no SHA3 verification
        let mut bytecode = vec![0x00; 50];
        bytecode[10..14].copy_from_slice(&[0x4e, 0x71, 0xd9, 0x2d]); // claim()
        bytecode[20] = 0xf1; // CALL (transfer)
        // No 0x20 (SHA3) for merkle verification
        
        let detector = MerkleAirdropDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(v.vulnerability_type, MerkleAirdropType::ClaimWithoutProof)));
    }
}
