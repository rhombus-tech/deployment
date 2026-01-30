use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IavlTreeProofForgeryVulnerability {
    pub location: usize,
    pub forgery_type: IavlForgeryType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IavlForgeryType {
    MissingProofVerification,        // No proof verification
    WeakMerkleValidation,            // Insufficient merkle proof checks
    UncheckedInnerHashPreimage,      // Inner hash preimage not validated
    LeafHashCollision,               // Leaf hash collision possible
    ProofDepthManipulation,          // Proof depth not bounded
    InvalidRangeProof,               // Range proof validation missing
}

pub struct IavlTreeProofForgeryDetector {
    bytecode: Vec<u8>,
}

impl IavlTreeProofForgeryDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<IavlTreeProofForgeryVulnerability> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_missing_proof_verification() {
            vulnerabilities.push(IavlTreeProofForgeryVulnerability {
                location: loc,
                forgery_type: IavlForgeryType::MissingProofVerification,
                severity: "Critical".to_string(),
                description: "IAVL tree proof verification is missing or insufficient. BNB Bridge $586M \
                             exploit: attacker forged IAVL proofs to create fake deposit events. Proof \
                             verification MUST validate entire merkle path.".to_string(),
                confidence: 0.95,
            });
        }

        if let Some(loc) = self.detect_weak_merkle_validation() {
            vulnerabilities.push(IavlTreeProofForgeryVulnerability {
                location: loc,
                forgery_type: IavlForgeryType::WeakMerkleValidation,
                severity: "Critical".to_string(),
                description: "Merkle proof validation is weak or incomplete. Does not verify root hash \
                             properly or allows partial path verification. Critical for cross-chain bridges.".to_string(),
                confidence: 0.92,
            });
        }

        if let Some(loc) = self.detect_unchecked_inner_hash() {
            vulnerabilities.push(IavlTreeProofForgeryVulnerability {
                location: loc,
                forgery_type: IavlForgeryType::UncheckedInnerHashPreimage,
                severity: "Critical".to_string(),
                description: "Inner node hash preimage not validated. Attacker can craft fake inner nodes \
                             to create valid-looking but fraudulent merkle paths.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_leaf_hash_collision() {
            vulnerabilities.push(IavlTreeProofForgeryVulnerability {
                location: loc,
                forgery_type: IavlForgeryType::LeafHashCollision,
                severity: "High".to_string(),
                description: "Leaf hash calculation vulnerable to collision. Does not properly domain-separate \
                             leaf hashes from inner node hashes, allowing forgery.".to_string(),
                confidence: 0.88,
            });
        }

        if let Some(loc) = self.detect_proof_depth_manipulation() {
            vulnerabilities.push(IavlTreeProofForgeryVulnerability {
                location: loc,
                forgery_type: IavlForgeryType::ProofDepthManipulation,
                severity: "High".to_string(),
                description: "Merkle proof depth not bounded. Allows extremely deep proofs that can bypass \
                             validation or cause DoS. Must enforce maximum proof depth.".to_string(),
                confidence: 0.86,
            });
        }

        if let Some(loc) = self.detect_invalid_range_proof() {
            vulnerabilities.push(IavlTreeProofForgeryVulnerability {
                location: loc,
                forgery_type: IavlForgeryType::InvalidRangeProof,
                severity: "High".to_string(),
                description: "IAVL range proof validation missing. Allows proving inclusion of keys outside \
                             valid range, enabling phantom deposits/withdrawals.".to_string(),
                confidence: 0.84,
            });
        }

        vulnerabilities
    }

    fn detect_missing_proof_verification(&self) -> Option<usize> {
        // Bridge verification function without proper merkle proof check
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                
                // Common bridge verification: verifyProof (0x1e8e1e13), processDeposit (0x0d0d9800)
                if selector == 0x1e8e1e13 || selector == 0x0d0d9800 {
                    // Check for SHA3 (merkle hashing) in verification
                    let mut has_hash_verification = false;
                    let mut hash_count = 0;
                    
                    for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                        if self.bytecode[j] == 0x20 { // SHA3
                            hash_count += 1;
                            if hash_count >= 3 { // Need multiple hashes for merkle path
                                has_hash_verification = true;
                                break;
                            }
                        }
                    }
                    
                    if !has_hash_verification {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_weak_merkle_validation(&self) -> Option<usize> {
        // Merkle verification without root hash comparison
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x20 { // SHA3 (hashing)
                // Check if followed by EQ comparison to root
                let mut has_root_compare = false;
                for j in i + 1..std::cmp::min(i + 45, self.bytecode.len()) {
                    if self.bytecode[j] == 0x14 { // EQ
                        // Check for SLOAD or CALLDATALOAD (root hash)
                        for k in j.saturating_sub(15)..j {
                            if self.bytecode[k] == 0x54 || self.bytecode[k] == 0x35 {
                                has_root_compare = true;
                                break;
                            }
                        }
                        if has_root_compare {
                            break;
                        }
                    }
                }
                
                // If we have multiple hashes but no root comparison
                let mut total_hashes = 0;
                for j in i..std::cmp::min(i + 45, self.bytecode.len()) {
                    if self.bytecode[j] == 0x20 {
                        total_hashes += 1;
                    }
                }
                
                if total_hashes >= 2 && !has_root_compare {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_unchecked_inner_hash(&self) -> Option<usize> {
        // Inner node construction without proper validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for concatenation followed by hash (merkle inner node)
            if matches!(self.bytecode[i], 0x60..=0x7f) { // PUSH
                // Check for MSTORE (building hash preimage)
                for j in i + 1..std::cmp::min(i + 10, self.bytecode.len()) {
                    if self.bytecode[j] == 0x52 { // MSTORE
                        // Check if followed by SHA3 without length check
                        for k in j + 1..std::cmp::min(j + 15, self.bytecode.len()) {
                            if self.bytecode[k] == 0x20 { // SHA3
                                // Check for length validation before hash
                                let mut has_length_check = false;
                                for m in j..k {
                                    if matches!(self.bytecode[m], 0x10 | 0x11 | 0x14) { // LT, GT, EQ
                                        has_length_check = true;
                                        break;
                                    }
                                }
                                if !has_length_check {
                                    return Some(i);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_leaf_hash_collision(&self) -> Option<usize> {
        // Leaf hash without domain separation
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x20 { // SHA3
                // Check if leaf hash has proper prefix (domain separation)
                let mut has_prefix = false;
                
                for j in i.saturating_sub(25)..i {
                    // Look for constant prefix PUSH (0x00 for leaf, 0x01 for inner)
                    if self.bytecode[j] == 0x60 && j + 1 < self.bytecode.len() {
                        if self.bytecode[j + 1] == 0x00 || self.bytecode[j + 1] == 0x01 {
                            has_prefix = true;
                            break;
                        }
                    }
                }
                
                if !has_prefix {
                    // This could be vulnerable to second-preimage attacks
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_proof_depth_manipulation(&self) -> Option<usize> {
        // Loop in proof verification without depth bound
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0x5b { // JUMPDEST (loop start)
                // Check for merkle proof loop (repeated hashing)
                let mut has_hash_in_loop = false;
                let mut has_depth_check = false;
                
                for j in i..std::cmp::min(i + 45, self.bytecode.len()) {
                    if self.bytecode[j] == 0x20 { // SHA3 in loop
                        has_hash_in_loop = true;
                    }
                    if self.bytecode[j] == 0x57 { // JUMPI (loop condition)
                        break;
                    }
                }
                
                // Check for counter/depth limit
                for j in i.saturating_sub(20)..i + 45 {
                    if j < self.bytecode.len() && matches!(self.bytecode[j], 0x10 | 0x11) { // LT or GT
                        has_depth_check = true;
                        break;
                    }
                }
                
                if has_hash_in_loop && !has_depth_check {
                    return Some(i);
                }
            }
        }
        None
    }

    fn detect_invalid_range_proof(&self) -> Option<usize> {
        // Range proof without bounds checking
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for range verification patterns
            if self.bytecode[i] == 0x20 { // SHA3 (proving)
                // Check if there's key range validation
                let mut has_range_check = false;
                
                for j in i..std::cmp::min(i + 35, self.bytecode.len()) {
                    // Look for double comparison (key >= min && key <= max)
                    if matches!(self.bytecode[j], 0x10 | 0x11) { // LT or GT
                        for k in j + 1..std::cmp::min(j + 15, self.bytecode.len()) {
                            if matches!(self.bytecode[k], 0x10 | 0x11) {
                                has_range_check = true;
                                break;
                            }
                        }
                        if has_range_check {
                            break;
                        }
                    }
                }
                
                // If this looks like proof verification but no range check
                let has_proof_pattern = i > 20 && {
                    let mut found = false;
                    for j in i.saturating_sub(20)..i {
                        if self.bytecode[j] == 0x63 && j + 4 < self.bytecode.len() {
                            let sel = u32::from_be_bytes([
                                self.bytecode[j + 1],
                                self.bytecode[j + 2],
                                self.bytecode[j + 3],
                                self.bytecode[j + 4],
                            ]);
                            if sel == 0x1e8e1e13 { // verifyProof
                                found = true;
                                break;
                            }
                        }
                    }
                    found
                };
                
                if has_proof_pattern && !has_range_check {
                    return Some(i);
                }
            }
        }
        None
    }
}
