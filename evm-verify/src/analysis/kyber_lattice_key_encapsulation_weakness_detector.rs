use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyberLatticeKemVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct KyberLatticeKeyEncapsulationWeaknessDetector {
    bytecode: Vec<u8>,
}

impl KyberLatticeKeyEncapsulationWeaknessDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<KyberLatticeKemVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_incorrect_parameter_set());
        vulnerabilities.extend(self.detect_weak_randomness_in_sampling());
        vulnerabilities.extend(self.detect_missing_ciphertext_validation());
        vulnerabilities
    }

    fn detect_incorrect_parameter_set(&self) -> Vec<KyberLatticeKemVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x60 && pc + 1 < self.bytecode.len() {
                let param_value = self.bytecode[pc + 1];
                if param_value < 2 || (param_value > 5 && param_value < 128) {
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let used_in_crypto = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x20).count() >= 2;
                    if used_in_crypto {
                        vulns.push(KyberLatticeKemVulnerability {
                            pc,
                            vulnerability_type: "IncorrectParameterSet".to_string(),
                            description: format!("Kyber parameter at PC {} uses non-standard security level, potentially weakening post-quantum security. Attack: Kyber KEM requires specific parameter sets (Kyber512, Kyber768, Kyber1024) for claimed security levels, custom parameters may reduce security to below quantum-resistant threshold. Real vulnerability: contract uses Kyber with n=128 instead of n=256, lattice dimension halved, security drops from 128-bit to ~64-bit against quantum attacks, Grover's algorithm breaks in 2^32 operations. Example: implementation sets k=1, n=128 instead of Kyber512's k=2, n=256, provides only 32-bit quantum security instead of 128-bit, post-quantum attacker breaks encryption. Missing: parameter validation against NIST standards. Should implement: require(n == 256 && k in [2,3,4]), validate against Kyber specification. Fix: use standardized Kyber parameter sets (Kyber512: k=2, Kyber768: k=3, Kyber1024: k=4), validate parameters match NIST PQC standards.", pc),
                            confidence: 0.76,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_weak_randomness_in_sampling(&self) -> Vec<KyberLatticeKemVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x20 { // SHA3 (used in sampling)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let uses_timestamp = self.bytecode[start..pc].iter().any(|&b| b == 0x42);
                let uses_blockhash = self.bytecode[start..pc].iter().any(|&b| b == 0x40);
                if uses_timestamp || uses_blockhash {
                    vulns.push(KyberLatticeKemVulnerability {
                        pc,
                        vulnerability_type: "WeakRandomnessInSampling".to_string(),
                        description: format!("Kyber polynomial sampling at PC {} uses weak randomness source, compromising security. Attack: Kyber requires cryptographically secure randomness for polynomial coefficient sampling, weak RNG allows attacker to predict secret key, decrypt all ciphertexts. Real attack: Kyber key generation uses blockhash for randomness, miner manipulates blockhash, predicts polynomial coefficients, derives secret key. Example: encapsulation uses block.timestamp as seed for rejection sampling, attacker knows timestamp, enumerates possible polynomials, recovers encapsulation key, decrypts shared secret. Missing: cryptographic RNG (CSPRNG), entropy from secure source. Should implement: use Keccak with sufficient entropy, not predictable blockchain state. Fix: require external entropy input from user or oracle, use commit-reveal for randomness, implement SHAKE-256 based deterministic RNG with unpredictable seed.", pc),
                        confidence: 0.84,
                    });
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_missing_ciphertext_validation(&self) -> Vec<KyberLatticeKemVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x35 { // CALLDATALOAD (ciphertext input)
                let window_end = (pc + 120).min(self.bytecode.len());
                let used_in_decaps = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x20).count() >= 3;
                if used_in_decaps {
                    let validates_ciphertext = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x10).count() >= 2;
                    if !validates_ciphertext {
                        vulns.push(KyberLatticeKemVulnerability {
                            pc,
                            vulnerability_type: "MissingCiphertextValidation".to_string(),
                            description: format!("Kyber decapsulation at PC {} doesn't validate ciphertext format, vulnerable to chosen-ciphertext attacks. Attack: attacker submits malformed ciphertext, decapsulation proceeds without validation, error messages or timing leak information about secret key, adaptive chosen-ciphertext attack recovers key. Real vulnerability: Kyber.Decaps() doesn't check ciphertext length or polynomial bounds, attacker sends ciphertext with coefficients > q, implementation behavior reveals secret, key extracted via 1000s of queries. Example: attacker submits ciphertext with c[0] = 2*q (invalid), decapsulation computes c[0] - s[0]*u mod q differently if overflow occurs, timing difference reveals bit of secret, repeat for all coefficients. Missing: ciphertext validation, re-encryption check. Should implement: validate len(ct) == expected, all coefficients < q, re-encrypt to verify. Fix: implement Fujisaki-Okamoto transform with implicit rejection, re-encrypt shared secret and compare ciphertext, reject if mismatch, constant-time operations.", pc),
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
}
