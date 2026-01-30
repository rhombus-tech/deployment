/// Decentralized Storage Vulnerability Detector
///
/// Detects vulnerabilities in IPFS, Arweave, Filecoin, and other decentralized storage integrations.
///
/// Critical vulnerabilities:
/// - **Unvalidated IPFS CID**: No verification of CID format or hash
/// - **Missing Content Verification**: URI stored without content hash validation
/// - **Mutable Storage References**: Using mutable IPNS instead of immutable IPFS
/// - **Censorship Risk**: Single storage provider, no redundancy
/// - **Metadata Tampering**: Off-chain metadata can be modified
///
/// Real exploits:
/// - **NFT Rugpull**: Attacker changes IPFS gateway, redirects to scam images
/// - **Metadata Manipulation**: Change NFT attributes after sale
/// - **Content Disappearance**: IPFS content unpinned, metadata becomes 404
/// - **Gateway Centralization**: Single gateway = single point of failure
///
/// Example vulnerability:
/// ```solidity
/// contract VulnerableNFT {
///     mapping(uint256 => string) public tokenURI;
///     
///     function setTokenURI(uint256 tokenId, string memory uri) external {
///         // ❌ VULNERABLE: No IPFS CID validation
///         // ❌ Owner can change URI anytime (rugpull)
///         // ❌ No content hash verification
///         tokenURI[tokenId] = uri;
///     }
///     
///     // Users expect immutable metadata, but owner can:
///     // 1. Change ipfs://QmXXX to malicious gateway
///     // 2. Point to different content
///     // 3. Break NFT metadata entirely
/// }
/// ```
///
/// Secure pattern:
/// ```solidity
/// contract SecureNFT {
///     // Store IPFS CID hash on-chain for verification
///     mapping(uint256 => bytes32) public contentHash;
///     string public constant BASE_URI = "ipfs://";
///     
///     function mint(uint256 tokenId, bytes32 ipfsHash) external {
///         require(ipfsHash != bytes32(0), "Invalid hash");
///         contentHash[tokenId] = ipfsHash;
///         // Metadata is now verifiable and immutable
///     }
/// }
/// ```

use crate::bytecode::security::SecuritySeverity;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DecentralizedStorageVulnerability {
    UnvalidatedIPFSCID { 
        description: String, 
        location: usize,
        confidence: f32,
    },
    MissingContentVerification { 
        description: String, 
        location: usize,
        confidence: f32,
    },
    MutableStorageReference { 
        description: String, 
        location: usize,
        confidence: f32,
    },
    SingleProviderRisk { 
        description: String, 
        location: usize,
        confidence: f32,
    },
    MetadataTamperingRisk { 
        description: String, 
        location: usize,
        confidence: f32,
    },
}

pub struct DecentralizedStorageDetector {
    bytecode: Vec<u8>,
}

impl DecentralizedStorageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DecentralizedStorageVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect unvalidated IPFS CID usage
        vulnerabilities.extend(self.detect_unvalidated_ipfs_cid());
        
        // Detect missing content hash verification
        vulnerabilities.extend(self.detect_missing_content_verification());
        
        // Detect mutable storage references (IPNS)
        vulnerabilities.extend(self.detect_mutable_storage_references());
        
        // Detect single provider centralization risk
        vulnerabilities.extend(self.detect_single_provider_risk());
        
        // Detect metadata tampering risks
        vulnerabilities.extend(self.detect_metadata_tampering_risk());

        vulnerabilities
    }

    fn detect_unvalidated_ipfs_cid(&self) -> Vec<DecentralizedStorageVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for string storage without CID validation
        // Pattern: SSTORE of string data without KECCAK256 verification
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check if preceded by MSTORE (string storage)
                let mut has_string_storage = false;
                let mut has_validation = false;

                // Look back for MSTORE pattern
                for j in i.saturating_sub(20)..i {
                    if self.bytecode[j] == 0x52 { // MSTORE
                        has_string_storage = true;
                    }
                    // Check for KECCAK256 or SHA3 validation
                    if self.bytecode[j] == 0x20 { // SHA3/KECCAK256
                        has_validation = true;
                    }
                }

                // Look ahead for validation
                for j in i+1..(i+20).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x20 { // SHA3/KECCAK256
                        has_validation = true;
                    }
                }

                if has_string_storage && !has_validation {
                    vulnerabilities.push(DecentralizedStorageVulnerability::UnvalidatedIPFSCID {
                        description: format!(
                            "String storage at PC {} without IPFS CID validation. \
                            Attacker can provide invalid or malicious CIDs. \
                            Add CID format validation and content hash verification.",
                            i
                        ),
                        location: i,
                        confidence: 0.75,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_missing_content_verification(&self) -> Vec<DecentralizedStorageVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Look for URI/string updates without hash verification
        // Pattern: External call (CALL/STATICCALL) followed by SSTORE without hash check
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if matches!(self.bytecode[i], 0xf1 | 0xfa) { // CALL or STATICCALL
                let mut has_sstore = false;
                let mut has_hash_check = false;

                // Check for SSTORE within next 30 bytes
                for j in i+1..(i+30).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0x55 { // SSTORE
                        has_sstore = true;
                    }
                    // Look for hash verification (SHA3, KECCAK256)
                    if self.bytecode[j] == 0x20 {
                        has_hash_check = true;
                    }
                }

                if has_sstore && !has_hash_check {
                    vulnerabilities.push(DecentralizedStorageVulnerability::MissingContentVerification {
                        description: format!(
                            "Storage update at PC {} without content hash verification. \
                            Off-chain content can be tampered with. \
                            Store and verify content hash on-chain.",
                            i
                        ),
                        location: i,
                        confidence: 0.70,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_mutable_storage_references(&self) -> Vec<DecentralizedStorageVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect usage of mutable IPNS references
        // Pattern: String update operations that suggest mutable references
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check if this is a string update (MSTORE + SSTORE pattern)
                let mut is_string_update = false;
                let mut is_owner_controlled = false;

                for j in i.saturating_sub(15)..i {
                    if self.bytecode[j] == 0x52 { // MSTORE
                        is_string_update = true;
                    }
                    // Check for CALLER comparison (owner check)
                    if self.bytecode[j] == 0x33 && j+1 < self.bytecode.len() && matches!(self.bytecode[j+1], 0x14 | 0x15) {
                        is_owner_controlled = true;
                    }
                }

                if is_string_update && is_owner_controlled {
                    vulnerabilities.push(DecentralizedStorageVulnerability::MutableStorageReference {
                        description: format!(
                            "Mutable storage reference at PC {}. \
                            Owner can change storage URI/CID after deployment. \
                            Use immutable IPFS CIDs, not mutable IPNS or centralized URLs.",
                            i
                        ),
                        location: i,
                        confidence: 0.68,
                    });
                }
            }
        }

        vulnerabilities
    }

    fn detect_single_provider_risk(&self) -> Vec<DecentralizedStorageVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect hardcoded single gateway/provider
        // Pattern: Multiple string comparisons suggesting gateway checks
        for i in 0..self.bytecode.len().saturating_sub(50) {
            let mut string_comparisons = 0;
            let mut has_fallback = false;

            // Count string equality checks in window
            for j in i..(i+50).min(self.bytecode.len()) {
                if matches!(self.bytecode[j], 0x14 | 0x15) { // EQ or ISZERO
                    if j > 0 && self.bytecode[j-1] == 0x52 { // Preceded by MSTORE
                        string_comparisons += 1;
                    }
                }
                // Check for JUMPI (indicates fallback logic)
                if self.bytecode[j] == 0x57 { // JUMPI
                    has_fallback = true;
                }
            }

            // Single provider if only 1-2 comparisons without fallback
            if string_comparisons >= 1 && string_comparisons <= 2 && !has_fallback {
                vulnerabilities.push(DecentralizedStorageVulnerability::SingleProviderRisk {
                    description: format!(
                        "Single storage provider dependency at PC {}. \
                        If gateway/provider goes down, content becomes inaccessible. \
                        Implement multiple gateways or provider fallback.",
                        i
                    ),
                    location: i,
                    confidence: 0.65,
                });
                break; // Only report once per function
            }
        }

        vulnerabilities
    }

    fn detect_metadata_tampering_risk(&self) -> Vec<DecentralizedStorageVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Detect tokenURI or metadata functions without immutability guarantees
        // Pattern: Function with SLOAD + RETURN without requiring immutability check
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x54 { // SLOAD (loading metadata)
                let mut has_return = false;
                let mut has_immutability_check = false;

                // Look ahead for RETURN
                for j in i+1..(i+30).min(self.bytecode.len()) {
                    if self.bytecode[j] == 0xf3 { // RETURN
                        has_return = true;
                    }
                    // Check for timestamp or block number check (immutability enforcement)
                    if matches!(self.bytecode[j], 0x42 | 0x43) { // TIMESTAMP or NUMBER
                        has_immutability_check = true;
                    }
                }

                // Look back for immutability patterns
                for j in i.saturating_sub(15)..i {
                    if matches!(self.bytecode[j], 0x42 | 0x43) {
                        has_immutability_check = true;
                    }
                }

                if has_return && !has_immutability_check {
                    vulnerabilities.push(DecentralizedStorageVulnerability::MetadataTamperingRisk {
                        description: format!(
                            "Metadata retrieval at PC {} without immutability guarantee. \
                            Off-chain metadata can be changed after mint. \
                            Lock metadata after reveal or use provenance hash.",
                            i
                        ),
                        location: i,
                        confidence: 0.72,
                    });
                    break; // One per function
                }
            }
        }

        vulnerabilities
    }
}
