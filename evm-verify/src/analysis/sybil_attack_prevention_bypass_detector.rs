use crate::bytecode::SecurityFinding;

pub struct SybilAttackPreventionBypassDetector {
    bytecode: Vec<u8>,
}

impl SybilAttackPreventionBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_missing_uniqueness_verification() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Sybil attack prevention can be bypassed without unique identity verification at PC {}. \
                    Single entity can create multiple identities.",
                    pc
                ),
                pc,
                confidence: 0.89,
            });
        }

        if let Some(pc) = self.detect_weak_proof_of_humanity() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Proof of humanity mechanism is weak and can be gamed at PC {}. \
                    Missing biometric or attestation verification.",
                    pc
                ),
                pc,
                confidence: 0.86,
            });
        }

        if let Some(pc) = self.detect_identity_rental_exploit() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Medium,
                description: format!(
                    "Identity can be transferred or rented, defeating sybil resistance at PC {}. \
                    Missing non-transferability enforcement.",
                    pc
                ),
                pc,
                confidence: 0.87,
            });
        }

        findings
    }

    fn detect_missing_uniqueness_verification(&self) -> Option<usize> {
        // Look for voting/reward/allocation functions without uniqueness checks
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // vote, claim, register, participate selectors
                if matches!(selector, [0x01, 0x2e, _, _] | [0x4e, 0x71, _, _] | [0x6f, 0xf0, _, _] | [0x7a, 0xcd, _, _]) {
                    let mut has_unique_check = false;
                    let mut has_poh_verification = false;
                    let mut has_did_verification = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for Proof of Humanity verification
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // isRegistered, isVerified, isHuman selectors for PoH contracts
                            if matches!(sub_selector, [0xc3, 0x2a, _, _] | [0xd4, 0x5b, _, _] | [0xe1, 0x7c, _, _]) {
                                has_poh_verification = true;
                            }
                            // DID registry verification
                            if matches!(sub_selector, [0xa2, 0x3f, _, _] | [0xb9, 0x4d, _, _]) {
                                has_did_verification = true;
                            }
                        }
                        // Check for biometric hash verification (comparing stored hash)
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x20 && // KECCAK256
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x54 && // SLOAD
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x14 { // EQ
                                has_unique_check = true;
                            }
                        }
                    }
                    
                    if !has_unique_check && !has_poh_verification && !has_did_verification {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_weak_proof_of_humanity(&self) -> Option<usize> {
        // Look for weak or gameable PoH mechanisms
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // registerHuman, verifyHuman, proveHuman selectors
                if matches!(selector, [0x8a, 0x4f, _, _] | [0x9c, 0x7e, _, _] | [0xad, 0x92, _, _]) {
                    let mut has_biometric = false;
                    let mut has_video_verification = false;
                    let mut has_attestation = false;
                    let mut has_weak_selfie_check = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Check for biometric verification (hash comparison of biometric data)
                        if j + 3 < self.bytecode.len() {
                            if self.bytecode[j] == 0x20 { // KECCAK256
                                has_biometric = true;
                            }
                        }
                        // Check for external attestation verification
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // verifyAttestation, checkProof selectors
                            if matches!(sub_selector, [0xc1, 0x8d, _, _] | [0xd2, 0x4e, _, _]) {
                                has_attestation = true;
                            }
                        }
                        // Detect simple selfie hash check (single KECCAK256 + SLOAD + EQ pattern)
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x20 && // KECCAK256
                               self.bytecode[j + 1] == 0x54 && // SLOAD
                               self.bytecode[j + 2] == 0x14 { // EQ
                                has_weak_selfie_check = true;
                            }
                        }
                    }
                    
                    // If only has weak selfie check without attestation or biometric verification
                    if has_weak_selfie_check && !has_attestation && !has_video_verification {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_identity_rental_exploit(&self) -> Option<usize> {
        // Look for identity tokens/NFTs that are transferable, defeating sybil resistance
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // transferFrom, safeTransferFrom for identity tokens
                if matches!(selector, [0x23, 0xb8, 0x72, 0xdd] | [0x42, 0x84, 0x2e, 0x0e]) {
                    let mut has_transfer_lock = false;
                    let mut has_soulbound_check = false;
                    
                    for j in i..i.saturating_add(50).min(self.bytecode.len()) {
                        // Check for soulbound/non-transferable flag
                        if j + 5 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 { // SLOAD (checking transferable flag)
                                if j + 3 < self.bytecode.len() && self.bytecode[j + 3] == 0x15 { // ISZERO
                                    has_soulbound_check = true;
                                }
                            }
                        }
                        // Check for permanent transfer lock
                        if j + 3 < self.bytecode.len() {
                            if self.bytecode[j] == 0x60 && self.bytecode[j + 1] == 0x00 && // PUSH1 0x00
                               self.bytecode[j + 2] == 0x56 { // JUMP (revert on transfer)
                                has_transfer_lock = true;
                            }
                        }
                    }
                    
                    if !has_transfer_lock && !has_soulbound_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
