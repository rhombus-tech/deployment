use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofBridgeVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct MerkleProofBridgeDetector {
    bytecode: Vec<u8>,
}

impl MerkleProofBridgeDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<MerkleProofBridgeVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_merkle_proof_forgery());
        vulnerabilities.extend(self.detect_proof_reuse_attack());
        vulnerabilities.extend(self.detect_incomplete_proof_validation());

        vulnerabilities
    }

    fn detect_merkle_proof_forgery(&self) -> Vec<MerkleProofBridgeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (merkle hashing)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_proof_verification = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                
                if has_proof_verification {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let has_root_comparison = forward.iter().any(|&b| b == 0x14); // EQ
                    let has_depth_check = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    let has_leaf_validation = window.iter().filter(|&&b| b == 0x20).count() >= 3;
                    
                    if has_root_comparison && !has_depth_check {
                        vulns.push(MerkleProofBridgeVulnerability {
                            pc,
                            vulnerability_type: "MerkleProofForgery".to_string(),
                            description: format!(
                                "Merkle proof verification at PC {} vulnerable to forgery attacks. Attack: bridge uses Merkle proofs to verify withdrawals, attacker \
                                exploits weak proof validation to forge proof for non-existent withdrawal. Common exploits: (1) depth manipulation - uses proof of wrong \
                                depth, (2) leaf/branch confusion - treats branch node as leaf, (3) second preimage - finds hash collision, (4) proof of exclusion - proves \
                                item NOT in tree but code interprets as inclusion. Missing: strict proof depth validation, leaf/branch node distinction, proper hash \
                                ordering validation. Should implement: verify proof.length == TREE_DEPTH, ensure leaf hash uses different domain than branch hash \
                                (e.g., prefix leaf with 0x00, branch with 0x01), validate sibling ordering.",
                                pc
                            ),
                            confidence: 0.88,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_proof_reuse_attack(&self) -> Vec<MerkleProofBridgeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (withdrawal tracking)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_merkle_verification = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                let has_withdrawal_execution = window.iter().any(|&b| b == 0xF1); // CALL
                
                if has_merkle_verification && has_withdrawal_execution {
                    let has_nullifier = window.iter().filter(|&&b| b == 0x55).count() >= 2;
                    let has_unique_identifier = window.iter().filter(|&&b| b == 0x20).count() >= 3;
                    
                    if !has_nullifier {
                        vulns.push(MerkleProofBridgeVulnerability {
                            pc,
                            vulnerability_type: "ProofReuseAttack".to_string(),
                            description: format!(
                                "Merkle proof withdrawal at PC {} allows proof reuse. Attack: user proves withdrawal from Merkle tree, withdraws funds, but proof not \
                                invalidated, user reuses same proof to withdraw again. Double-spend on bridge. Example: Merkle root contains withdrawal(user, 100 ETH, \
                                nonce=5), user submits valid proof and withdraws, proof still valid because root unchanged, submits again and gets another 100 ETH. Missing: \
                                withdrawal nullifier tracking (mark proof as used), nonce inclusion in leaf hash, proof expiry. Should implement: mapping(bytes32 \
                                withdrawalHash => bool claimed), leaf = keccak256(abi.encode(recipient, amount, UNIQUE_NONCE)), require(!claimed[leaf]), claimed[leaf] = true.",
                                pc
                            ),
                            confidence: 0.91,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_incomplete_proof_validation(&self) -> Vec<MerkleProofBridgeVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x14 { // EQ (root comparison)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_merkle_hashing = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                
                if has_merkle_hashing {
                    let has_empty_proof_check = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 1;
                    let has_malformed_proof_check = window.iter().any(|&b| b == 0x06); // MOD (length check)
                    let has_zero_root_check = window.iter().filter(|&&b| b == 0x15).count() >= 1; // ISZERO
                    
                    if !has_empty_proof_check || !has_zero_root_check {
                        vulns.push(MerkleProofBridgeVulnerability {
                            pc,
                            vulnerability_type: "IncompleteProofValidation".to_string(),
                            description: format!(
                                "Merkle proof validation at PC {} incomplete. Attack: bridge doesn't validate edge cases in proof verification, attacker exploits: \
                                (1) empty proof array - if proof.length == 0, verification might incorrectly succeed, (2) zero root - root = 0x0 should never be valid, \
                                (3) malformed proof - odd number of elements or invalid structure. Missing: proof length validation (must be 0 < length <= MAX_DEPTH), \
                                root != 0 check, proof structural validation. Should implement: require(proof.length > 0 && proof.length <= 32, 'Invalid proof length'), \
                                require(root != bytes32(0), 'Zero root'), validate each proof element is exactly 32 bytes.",
                                pc
                            ),
                            confidence: 0.84,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }
}
