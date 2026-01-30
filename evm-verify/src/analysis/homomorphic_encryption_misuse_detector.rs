use crate::bytecode::SecurityFinding;

pub struct HomomorphicEncryptionMisuseDetector {
    bytecode: Vec<u8>,
}

impl HomomorphicEncryptionMisuseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SecurityFinding> {
        self.detect()
    }
    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_noise_budget_exhaustion() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Homomorphic encryption noise budget can be exhausted at PC {}. \
                    Excessive chained operations degrade ciphertext quality leading to incorrect decryption.",
                    pc
                ),
                pc,
                confidence: 0.89,
            });
        }

        if let Some(pc) = self.detect_plaintext_leakage() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Homomorphic computation may leak plaintext information at PC {}. \
                    Side-channel vulnerable operations expose encrypted data.",
                    pc
                ),
                pc,
                confidence: 0.87,
            });
        }

        if let Some(pc) = self.detect_key_switching_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Homomorphic key switching lacks proper validation at PC {}. \
                    Malicious key switches can compromise encrypted computations.",
                    pc
                ),
                pc,
                confidence: 0.85,
            });
        }

        findings
    }

    fn detect_noise_budget_exhaustion(&self) -> Option<usize> {
        // Look for excessive homomorphic operations without relinearization
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // heMultiply, heAdd, heModulus selectors
                if matches!(selector, [0xa1, 0x3e, _, _] | [0xb2, 0x4f, _, _] | [0xc3, 0x5d, _, _]) {
                    let mut operation_count = 0;
                    let mut has_relinearization = false;
                    let mut checks_noise_budget = false;
                    
                    for j in i..i.saturating_add(100).min(self.bytecode.len()) {
                        // Count multiplicative operations
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            if matches!(sub_selector, [0xa1, 0x3e, _, _]) {
                                operation_count += 1;
                            }
                            // Check for relinearization call
                            if matches!(sub_selector, [0xd4, 0x6e, _, _]) {
                                has_relinearization = true;
                            }
                        }
                        // Check for noise budget validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (noise level)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x10 && // LT (checking limit)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x15 { // ISZERO
                                checks_noise_budget = true;
                            }
                        }
                    }
                    
                    if operation_count >= 3 && !has_relinearization && !checks_noise_budget {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_plaintext_leakage(&self) -> Option<usize> {
        // Look for timing-dependent operations on encrypted data
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // heCompare, heDecrypt, heEvaluate selectors
                if matches!(selector, [0xe1, 0x4f, _, _] | [0xf2, 0x5c, _, _] | [0xa3, 0x6d, _, _]) {
                    let mut uses_conditional_logic = false;
                    let mut has_constant_time = false;
                    let mut validates_encryption = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for conditional branches (timing leak)
                        if self.bytecode[j] == 0x57 { // JUMPI
                            uses_conditional_logic = true;
                        }
                        // Check for constant-time operation flag
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (constant_time flag)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x15 { // ISZERO
                                has_constant_time = true;
                            }
                        }
                        // Check for encryption validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (ciphertext)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x54 && // SLOAD (public key)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x14 { // EQ
                                validates_encryption = true;
                            }
                        }
                    }
                    
                    if uses_conditional_logic && !has_constant_time {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_key_switching_vulnerability(&self) -> Option<usize> {
        // Look for key switching without proper authorization
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // switchKey, updatePublicKey, rotateKey selectors
                if matches!(selector, [0xd1, 0x3e, _, _] | [0xe2, 0x4f, _, _] | [0xf3, 0x5c, _, _]) {
                    let mut validates_new_key = false;
                    let mut has_authorization = false;
                    let mut checks_key_compatibility = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for key validation
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (new key)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x20 && // KECCAK256
                               j + 8 < self.bytecode.len() &&
                               self.bytecode[j + 7] == 0x54 { // SLOAD (comparing)
                                validates_new_key = true;
                            }
                        }
                        // Check for authorization
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x33 && // CALLER
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x54 && // SLOAD (owner)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x14 { // EQ
                                has_authorization = true;
                            }
                        }
                        // Check for key compatibility (modulus match)
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (old key params)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x35 && // CALLDATALOAD (new key params)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x14 { // EQ
                                checks_key_compatibility = true;
                            }
                        }
                    }
                    
                    if !validates_new_key || !has_authorization {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
