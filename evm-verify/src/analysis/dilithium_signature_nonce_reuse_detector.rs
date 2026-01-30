use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DilithiumSignatureNonceVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct DilithiumSignatureNonceReuseDetector {
    bytecode: Vec<u8>,
}

impl DilithiumSignatureNonceReuseDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<DilithiumSignatureNonceVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_deterministic_nonce_without_message());
        vulnerabilities.extend(self.detect_nonce_state_not_cleared());
        vulnerabilities.extend(self.detect_weak_nonce_generation());
        vulnerabilities
    }

    fn detect_deterministic_nonce_without_message(&self) -> Vec<DilithiumSignatureNonceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x20 { // SHA3 (nonce generation)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let has_secret_key = self.bytecode[start..pc].iter().filter(|&&b| b == 0x54).count() >= 2;
                if has_secret_key {
                    let includes_message = self.bytecode[start..pc].iter().any(|&b| b == 0x35);
                    if !includes_message {
                        vulns.push(DilithiumSignatureNonceVulnerability {
                            pc,
                            vulnerability_type: "DeterministicNonceWithoutMessage".to_string(),
                            description: format!("Dilithium nonce generation at PC {} doesn't include message in hash, enabling nonce reuse attack. Attack: Dilithium signature nonce y must be derived from (secret_key || message), nonce generation without message creates deterministic nonce independent of message, signing two different messages yields same nonce, algebraic attack recovers secret key. Real attack: Sign(sk, m1) and Sign(sk, m2) both use nonce y = H(sk), attacker computes signature difference, solves for secret polynomial s. Example: two signatures (z1, h1) and (z2, h2) with same y, attacker computes z1 - z2 = c1*s1 - c2*s2 (mod q), multiple equations reveal s. Missing: message input to nonce derivation. Should implement: y = SHAKE256(sk || rho || mu) where mu = H(message). Fix: include message hash in nonce generation, use Dilithium's specified nonce derivation with message dependency, never reuse nonce across different messages.", pc),
                            confidence: 0.87,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_nonce_state_not_cleared(&self) -> Vec<DilithiumSignatureNonceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (state update)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let stores_nonce = self.bytecode[start..pc].iter().filter(|&&b| b == 0x20).count() >= 1;
                if stores_nonce {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let cleared_after_use = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x55).count() >= 1;
                    if !cleared_after_use {
                        vulns.push(DilithiumSignatureNonceVulnerability {
                            pc,
                            vulnerability_type: "NonceStateNotCleared".to_string(),
                            description: format!("Dilithium nonce stored at PC {} not cleared after signature generation, allowing nonce extraction and key recovery. Attack: signature nonce y persists in storage after signing, attacker reads storage, extracts nonce, combines with signature to algebraically solve for secret key. Real vulnerability: contract stores intermediate signing values in state variables, y not zeroed after signature creation, attacker calls signature function, reads storage slot, obtains y. Example: Sign() computes y and stores temporarily, returns signature (z, c, h), y remains in storage, attacker extracts y, combines with z and c to derive secret s via lattice reduction. Missing: memory zeroization after use. Should implement: delete nonce_storage after signature generation. Fix: zero all intermediate signing variables, use memory instead of storage for nonce, implement explicit cleanup after signature generation.", pc),
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

    fn detect_weak_nonce_generation(&self) -> Vec<DilithiumSignatureNonceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x20 { // SHA3 (nonce hash)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let uses_weak_input = self.bytecode[start..pc].iter().filter(|&&b| matches!(b, 0x42 | 0x43 | 0x44)).count() >= 1;
                if uses_weak_input {
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let used_for_signing = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x02).count() >= 3;
                    if used_for_signing {
                        vulns.push(DilithiumSignatureNonceVulnerability {
                            pc,
                            vulnerability_type: "WeakNonceGeneration".to_string(),
                            description: format!("Dilithium nonce generation at PC {} uses weak randomness source, enabling nonce prediction. Attack: nonce derived from block.timestamp or similar predictable source, attacker predicts nonce, pre-computes signature relationships, performs lattice attack on signature to recover secret key. Real attack: y = H(block.timestamp || sk), attacker knows timestamp range (within 15s), bruteforces possible nonce values, for each computes expected signature component z, compares with actual signature, extracts key material. Example: nonce uses block.number, attacker sees signature in tx at block N, knows y = H(N || sk), simulates signature generation, solves system of equations for secret polynomial. Missing: cryptographically secure unpredictable entropy. Should implement: y = SHAKE256(sk || rho || random_seed) with user-provided randomness. Fix: require external entropy, use commit-reveal for seed, implement RFC 8032 style deterministic signatures with proper message binding.", pc),
                            confidence: 0.79,
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
