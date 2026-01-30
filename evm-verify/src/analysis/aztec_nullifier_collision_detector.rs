use crate::bytecode::SecurityFinding;

pub struct AztecNullifierCollisionDetector {
    bytecode: Vec<u8>,
}

impl AztecNullifierCollisionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_weak_nullifier_generation() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Aztec nullifier generation uses weak or predictable inputs at PC {}. \
                    Nullifier collisions enable double-spending of notes.",
                    pc
                ),
                pc,
                confidence: 0.93,
            });
        }

        if let Some(pc) = self.detect_missing_nullifier_uniqueness() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Nullifier uniqueness not enforced at PC {}. \
                    Missing storage checks allow nullifier reuse and double-spending.",
                    pc
                ),
                pc,
                confidence: 0.95,
            });
        }

        if let Some(pc) = self.detect_note_commitment_bypass() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Note commitment verification can be bypassed at PC {}. \
                    Invalid notes can be spent without proper Merkle proof validation.",
                    pc
                ),
                pc,
                confidence: 0.89,
            });
        }

        findings
    }

    fn detect_weak_nullifier_generation(&self) -> Option<usize> {
        // Look for nullifier computation with insufficient entropy
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // computeNullifier, generateNullifier selectors
                if matches!(selector, [0x8a, 0x4f, _, _] | [0x9b, 0x6e, _, _]) {
                    let mut uses_keccak = false;
                    let mut input_count = 0;
                    let mut has_secret_input = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Count inputs to hash function
                        if self.bytecode[j] == 0x35 { // CALLDATALOAD
                            input_count += 1;
                        }
                        // Check for KECCAK256
                        if self.bytecode[j] == 0x20 { // KECCAK256
                            uses_keccak = true;
                        }
                        // Check for secret/private key usage
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // getSecret, loadPrivateKey selectors
                            if matches!(sub_selector, [0xd2, 0x3f, _, _] | [0xe4, 0x5d, _, _]) {
                                has_secret_input = true;
                            }
                        }
                    }
                    
                    // Nullifier needs sufficient inputs (note commitment + secret)
                    if uses_keccak && (input_count < 2 || !has_secret_input) {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_missing_nullifier_uniqueness(&self) -> Option<usize> {
        // Look for nullifier usage without storage checks
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // processNote, spendNote, submitProof selectors
                if matches!(selector, [0x7a, 0x3e, _, _] | [0x8c, 0x4f, _, _] | [0x9e, 0x6d, _, _]) {
                    let mut computes_nullifier = false;
                    let mut checks_storage = false;
                    let mut stores_nullifier = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check for nullifier computation
                        if self.bytecode[j] == 0x20 { // KECCAK256
                            computes_nullifier = true;
                        }
                        // Check for storage lookup (checking if nullifier already used)
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x15 { // ISZERO (checking if unused)
                                checks_storage = true;
                            }
                        }
                        // Check for nullifier storage
                        if self.bytecode[j] == 0x55 { // SSTORE
                            stores_nullifier = true;
                        }
                    }
                    
                    if computes_nullifier && (!checks_storage || !stores_nullifier) {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_note_commitment_bypass(&self) -> Option<usize> {
        // Look for note spending without proper Merkle proof verification
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // spendNote, processWithdrawal selectors
                if matches!(selector, [0x8c, 0x4f, _, _] | [0xa1, 0x6e, _, _]) {
                    let mut has_merkle_verification = false;
                    let mut has_root_check = false;
                    let mut spends_note = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for Merkle proof verification (multiple KECCAK256 calls)
                        if j + 20 < self.bytecode.len() {
                            let mut keccak_count = 0;
                            for k in j..j + 20 {
                                if self.bytecode[k] == 0x20 { // KECCAK256
                                    keccak_count += 1;
                                }
                            }
                            if keccak_count >= 3 { // Typical Merkle proof depth
                                has_merkle_verification = true;
                            }
                        }
                        // Check for root comparison
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (loading root)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x14 { // EQ (comparing roots)
                                has_root_check = true;
                            }
                        }
                        // Check if actually spending note
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // transfer, withdraw selectors
                            if matches!(sub_selector, [0xa9, 0x05, 0x9c, 0xbb] | [0x2e, 0x1a, 0x7d, 0x4d]) {
                                spends_note = true;
                            }
                        }
                    }
                    
                    if spends_note && (!has_merkle_verification || !has_root_check) {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
