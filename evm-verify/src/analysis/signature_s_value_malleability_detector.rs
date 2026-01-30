use serde::{Serialize, Deserialize};

/// Signature S-Value Malleability Detector
/// 
/// ECDSA signatures have inherent malleability: for every valid signature (r,s),
/// there exists another valid signature (r, -s mod n) for the same message.
/// This was exploited in Bitcoin (BIP-62) and must be prevented.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureSValueMalleabilityVulnerability {
    /// Critical: S value not validated for malleability
    SValueNotValidated {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// High: ecrecover without s <= secp256k1n/2 check
    EcrecoverNoSCheck {
        description: String,
        location: usize,
    },
    /// High: Signature hash used for replay protection
    SignatureHashReplayProtection {
        description: String,
        location: usize,
    },
    /// Medium: OpenZeppelin ECDSA library not used
    NoECDSALibrary {
        description: String,
        location: usize,
    },
}

pub struct SignatureSValueMalleabilityDetector {
    bytecode: Vec<u8>,
}

impl SignatureSValueMalleabilityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SignatureSValueMalleabilityVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Find all ecrecover calls
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.is_ecrecover_call(i) {
                // Check if s value is validated
                if !self.has_s_value_validation(i, i + 60) {
                    vulnerabilities.push(SignatureSValueMalleabilityVulnerability::EcrecoverNoSCheck {
                        description: "ecrecover without s value malleability check - signature can be modified".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Check for signature hash-based replay protection (vulnerable to malleability)
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.uses_signature_hash_for_replay(i, i + 40) {
                vulnerabilities.push(SignatureSValueMalleabilityVulnerability::SignatureHashReplayProtection {
                    description: "Uses signature hash for replay protection - malleable signatures bypass this".to_string(),
                    location: i,
                });
            }
        }
        
        // Check if OpenZeppelin ECDSA library patterns are present
        if !self.uses_ecdsa_library() {
            vulnerabilities.push(SignatureSValueMalleabilityVulnerability::NoECDSALibrary {
                description: "Contract does not appear to use OpenZeppelin ECDSA library which handles s-value malleability".to_string(),
                location: 0,
            });
        }
        
        vulnerabilities
    }
    
    fn is_ecrecover_call(&self, location: usize) -> bool {
        if location + 10 > self.bytecode.len() {
            return false;
        }
        
        // ecrecover precompile at 0x01
        for offset in 0..8 {
            if location + offset + 2 < self.bytecode.len() {
                if self.bytecode[location + offset] == 0x60 && 
                   self.bytecode[location + offset + 1] == 0x01 {
                    for j in (location + offset + 2)..(location + offset + 12).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0xFA || self.bytecode[j] == 0xF1 {
                            return true;
                        }
                    }
                }
            }
        }
        
        false
    }
    
    fn has_s_value_validation(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // S value must be <= secp256k1n / 2
        // secp256k1n/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        // Look for this constant or similar validation
        
        for i in start..range_end.saturating_sub(32) {
            // Look for PUSH32 with 0x7F prefix (half of secp256k1 order)
            if self.bytecode[i] == 0x7F { // PUSH32
                if i + 1 < range_end && self.bytecode[i + 1] == 0xFF {
                    // Found potential secp256k1n/2 constant
                    // Check for GT or LT comparison
                    for j in i..i.saturating_add(40).min(range_end) {
                        if self.bytecode[j] == 0x10 || // LT
                           self.bytecode[j] == 0x11 { // GT
                            return true;
                        }
                    }
                }
            }
        }
        
        false
    }
    
    fn uses_signature_hash_for_replay(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Pattern: keccak256(abi.encodePacked(r, s, v)) stored as "used"
        // This is vulnerable because malleable s produces different hash
        
        let mut has_keccak_of_signature = false;
        let mut has_sstore_after = false;
        
        for i in start..range_end {
            // KECCAK256 opcode
            if self.bytecode[i] == 0x20 {
                has_keccak_of_signature = true;
            }
            
            // SSTORE after keccak
            if has_keccak_of_signature && self.bytecode[i] == 0x55 {
                has_sstore_after = true;
            }
        }
        
        has_keccak_of_signature && has_sstore_after
    }
    
    fn uses_ecdsa_library(&self) -> bool {
        // OpenZeppelin ECDSA.recover function selector: varies
        // Look for s-value validation pattern which is characteristic
        
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x7F && // PUSH32
               i + 1 < self.bytecode.len() &&
               self.bytecode[i + 1] == 0xFF {
                // secp256k1n/2 constant suggests OpenZeppelin ECDSA
                return true;
            }
        }
        
        false
    }
}
