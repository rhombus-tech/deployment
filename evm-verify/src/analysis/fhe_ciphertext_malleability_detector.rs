use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FheCiphertextMalleabilityVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct FheCiphertextMalleabilityDetector {
    bytecode: Vec<u8>,
}

impl FheCiphertextMalleabilityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<FheCiphertextMalleabilityVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_unverified_ciphertext_operations());
        vulnerabilities.extend(self.detect_missing_ciphertext_authentication());
        vulnerabilities.extend(self.detect_homomorphic_operation_overflow());
        vulnerabilities
    }

    fn detect_unverified_ciphertext_operations(&self) -> Vec<FheCiphertextMalleabilityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x02 { // MUL (homomorphic multiplication)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let operates_on_ciphertext = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 2;
                if operates_on_ciphertext {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let verifies_result = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x14).count() >= 1;
                    if !verifies_result {
                        vulns.push(FheCiphertextMalleabilityVulnerability {
                            pc,
                            vulnerability_type: "UnverifiedCiphertextOperations".to_string(),
                            description: format!("FHE operation at PC {} doesn't verify ciphertext integrity, enabling malleability attacks. Attack: homomorphic encryption allows operations on ciphertexts, without verification attacker modifies ciphertext, changes encrypted value unpredictably, breaks computation correctness. Real attack: FHE auction stores encrypted bids, attacker intercepts ciphertext, multiplies by 2 homomorphically, their bid doubled without decryption, wins auction unfairly. Example: encrypted voting ciphertext = Enc(vote), attacker computes Enc(vote) * Enc(100), modifies encrypted vote total, election results manipulated. Missing: ciphertext authentication, zero-knowledge proof of operation correctness. Should implement: verify ciphertext came from trusted source, validate homomorphic operations. Fix: use authenticated encryption, require ZK proof that operation performed correctly, implement ciphertext version/nonce to detect modifications, validate all ciphertexts before homomorphic operations.", pc),
                            confidence: 0.81,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_missing_ciphertext_authentication(&self) -> Vec<FheCiphertextMalleabilityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (ciphertext storage)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let stores_ciphertext = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 1;
                if stores_ciphertext {
                    let has_authentication_tag = self.bytecode[start..pc].iter().filter(|&&b| b == 0x20).count() >= 1;
                    if !has_authentication_tag {
                        vulns.push(FheCiphertextMalleabilityVulnerability {
                            pc,
                            vulnerability_type: "MissingCiphertextAuthentication".to_string(),
                            description: format!("Ciphertext storage at PC {} lacks authentication, allowing substitution attacks. Attack: FHE ciphertext stored without MAC or signature, attacker replaces with different valid ciphertext, computation result altered, privacy/correctness broken. Real vulnerability: encrypted medical record Enc(diagnosis), attacker replaces with Enc(different_diagnosis), doctor receives wrong encrypted data, treatment compromised. Example: FHE smart contract stores Enc(balance), attacker replaces Alice's Enc(100) with Enc(1000), decryption reveals inflated balance, fund accounting broken. Missing: ciphertext authentication tag, digital signature on ciphertexts. Should implement: MAC or signature on each ciphertext, verify before use. Fix: use HMAC(ciphertext, key) stored alongside ciphertext, verify HMAC before any operation, or use public-key signatures for multi-party scenarios, implement ciphertext binding to user identity.", pc),
                            confidence: 0.83,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_homomorphic_operation_overflow(&self) -> Vec<FheCiphertextMalleabilityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x01 { // ADD (homomorphic addition)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let adds_ciphertexts = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 2;
                if adds_ciphertexts {
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let checks_noise = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x10).count() >= 1;
                    if !checks_noise {
                        vulns.push(FheCiphertextMalleabilityVulnerability {
                            pc,
                            vulnerability_type: "HomomorphicOperationOverflow".to_string(),
                            description: format!("Homomorphic operation at PC {} doesn't check noise accumulation, risking decryption failure. Attack: FHE schemes accumulate noise with each operation, excessive operations cause noise overflow, decryption returns garbage, computation useless or exploitable. Real vulnerability: FHE addition performed 1000 times, noise exceeds ciphertext modulus, decryption fails or produces wrong plaintext, breaks application logic. Example: encrypted counter incremented many times, noise grows, Decrypt(ciphertext) returns random value instead of count, protocol state corrupted. Missing: noise budget tracking, operation limits, bootstrapping. Should implement: track multiplicative depth, limit operations before bootstrapping. Fix: implement noise budget counter, bootstrap ciphertext when noise threshold reached, limit consecutive operations, use leveled FHE with appropriate parameters for computation depth, validate noise level before critical decryptions.", pc),
                            confidence: 0.77,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }
}
