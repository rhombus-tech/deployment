use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc5334Eip1155ExtensionVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct Erc5334Eip1155ExtensionDetector {
    bytecode: Vec<u8>,
}

impl Erc5334Eip1155ExtensionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc5334Eip1155ExtensionVulnerability> {
        let mut vulnerabilities = Vec::new();

        // ERC-5334 extends EIP-1155 with additional metadata
        // Detect token ID collision
        if let Some(location) = self.has_token_id_collision() {
            vulnerabilities.push(Erc5334Eip1155ExtensionVulnerability {
                vulnerability_type: "ERC-5334 Token ID Collision".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Token ID generation without collision prevention. Multiple tokens could share same ID causing balance/ownership confusion. Use sequential IDs or check existence before minting.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect metadata inconsistency
        if let Some(location) = self.has_metadata_inconsistency() {
            vulnerabilities.push(Erc5334Eip1155ExtensionVulnerability {
                vulnerability_type: "ERC-5334 Metadata Inconsistency".to_string(),
                location,
                severity: "High".to_string(),
                description: "Extended metadata can be modified independently of token state. Metadata could be changed after mint violating immutability expectations. Link metadata lifecycle to token.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect batch operation atomicity violation
        if let Some(location) = self.has_batch_atomicity_violation() {
            vulnerabilities.push(Erc5334Eip1155ExtensionVulnerability {
                vulnerability_type: "ERC-5334 Batch Operation Atomicity".to_string(),
                location,
                severity: "High".to_string(),
                description: "Batch operations don't enforce atomicity. Partial execution on failure could leave state inconsistent. Implement proper reversion on any failure in batch.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_token_id_collision(&self) -> Option<usize> {
        // Pattern: Token ID storage (SSTORE) without existence check
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0x55 { // SSTORE (new token)
                // Check for existence validation (SLOAD + ISZERO)
                let mut has_existence_check = false;
                
                for j in i.saturating_sub(20)..i {
                    if self.bytecode[j] == 0x54 { // SLOAD (checking if exists)
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 { // ISZERO (must not exist)
                                has_existence_check = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_existence_check {
                    // Verify this is token creation (mint pattern)
                    for j in i.saturating_sub(15)..i {
                        if self.bytecode[j] == 0x35 { // CALLDATALOAD (tokenId)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_metadata_inconsistency(&self) -> Option<usize> {
        // Pattern: Metadata storage write without token state validation
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 { // SSTORE (metadata)
                // Check if token existence is validated first
                let mut has_token_check = false;
                
                for j in i.saturating_sub(25)..i {
                    if self.bytecode[j] == 0x54 { // SLOAD (checking token exists)
                        // Look for non-zero check
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 { // ISZERO
                                // Followed by conditional (token must exist)
                                for m in k+1..(k+5).min(self.bytecode.len()).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0x57 { // JUMPI
                                        has_token_check = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                
                if !has_token_check {
                    // Verify this looks like metadata (URI or similar)
                    for j in i.saturating_sub(15)..i {
                        if self.bytecode[j] == 0x51 || self.bytecode[j] == 0x52 { // MLOAD/MSTORE
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_batch_atomicity_violation(&self) -> Option<usize> {
        // Pattern: Loop with state changes but no revert on failure
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for loop pattern (JUMPDEST + counter)
            if self.bytecode[i] == 0x5b { // JUMPDEST (loop start)
                let mut has_sstore = false;
                let mut has_revert_on_failure = false;
                
                // Check loop body for state changes
                let upper_bound = (i + 50).min(self.bytecode.len());
                for j in (i+1)..upper_bound {
                    if j >= self.bytecode.len() { break; }
                    if self.bytecode[j] == 0x55 { // SSTORE (state change)
                        has_sstore = true;
                    }
                    // Look for failure handling (ISZERO + JUMPI to REVERT)
                    if self.bytecode[j] == 0x15 { // ISZERO (checking success)
                        for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x57 { // JUMPI
                                for m in k+1..(k+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                                    if self.bytecode[m] == 0xfd { // REVERT
                                        has_revert_on_failure = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                
                // If loop has state changes but no proper revert handling
                if has_sstore && !has_revert_on_failure {
                    return Some(i);
                }
            }
        }
        None
    }
}
