use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtlcHashPreimageBruteForceVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct HtlcHashPreimageBruteForceDetector {
    bytecode: Vec<u8>,
}

impl HtlcHashPreimageBruteForceDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<HtlcHashPreimageBruteForceVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_weak_hash_preimage());
        vulnerabilities.extend(self.detect_insufficient_preimage_entropy());
        vulnerabilities.extend(self.detect_predictable_secret_generation());
        vulnerabilities
    }

    fn detect_weak_hash_preimage(&self) -> Vec<HtlcHashPreimageBruteForceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x14 { // EQ (hash comparison)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let compares_hash = self.bytecode[start..pc].iter().filter(|&&b| b == 0x20).count() >= 1;
                if compares_hash {
                    let hash_size_check = self.bytecode[start..pc].iter().filter(|&&b| b == 0x60).any(|_| true);
                    if hash_size_check {
                        let window_end = (pc + 80).min(self.bytecode.len());
                        let releases_funds = self.bytecode[pc..window_end].iter().any(|&b| b == 0xF1);
                        if releases_funds {
                            vulns.push(HtlcHashPreimageBruteForceVulnerability {
                                pc,
                                vulnerability_type: "WeakHashPreimage".to_string(),
                                description: format!("HTLC hash verification at PC {} may use weak preimage enabling brute force. Attack: HTLC uses short or low-entropy hash preimage, attacker brute forces preimage offline, claims funds on both chains, defeats atomic swap. Real attack: Lightning Network HTLC uses 160-bit payment hash, attacker with ASIC brute forces preimage in hours if entropy insufficient, claims payment without providing service. Example: atomic swap secret = hash(timestamp), attacker knows approximate timestamp range, brute forces 2^32 possibilities, finds preimage, claims funds on both chains. Missing: minimum preimage entropy requirement, preimage length validation. Should implement: require(preimage.length >= 32), validate entropy via hash distribution. Fix: enforce 256-bit preimage minimum, use cryptographically secure random generation, include user-provided randomness in preimage generation.", pc),
                                confidence: 0.81,
                            });
                        }
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_insufficient_preimage_entropy(&self) -> Vec<HtlcHashPreimageBruteForceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x20 { // SHA3 (secret hash)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let uses_predictable_input = self.bytecode[start..pc].iter().filter(|&&b| matches!(b, 0x42 | 0x43)).count() >= 1;
                if uses_predictable_input {
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let used_in_htlc = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x55).count() >= 1;
                    if used_in_htlc {
                        vulns.push(HtlcHashPreimageBruteForceVulnerability {
                            pc,
                            vulnerability_type: "InsufficientPreimageEntropy".to_string(),
                            description: format!("HTLC secret generation at PC {} uses predictable entropy source, enabling preimage prediction. Attack: secret derived from block.timestamp or block.number, attacker predicts future values, pre-computes hash, waits for HTLC creation, immediately claims. Real vulnerability: swap secret = keccak256(block.timestamp), timestamp known/predictable, attacker computes hash before HTLC funded, initiates claim transaction same block. Example: cross-chain swap creates HTLC with hashlock = hash(block.number + 100), attacker predicts block.number progression, pre-computes secrets for blocks N to N+1000, instantly claims when HTLC created. Missing: unpredictable randomness, user-provided entropy. Should implement: secret from user input or VRF, not blockchain state. Fix: require user provides random secret, or use commit-reveal with off-chain randomness, validate secret has sufficient entropy (e.g., > 128 bits).", pc),
                            confidence: 0.84,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_predictable_secret_generation(&self) -> Vec<HtlcHashPreimageBruteForceVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x20 { // SHA3
                let start = if pc > 100 { pc - 100 } else { 0 };
                let uses_sequential_input = self.bytecode[start..pc].iter().filter(|&&b| matches!(b, 0x01 | 0x02)).count() >= 1;
                if uses_sequential_input {
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let stored_as_hashlock = self.bytecode[pc..window_end].iter().any(|&b| b == 0x55);
                    if stored_as_hashlock {
                        vulns.push(HtlcHashPreimageBruteForceVulnerability {
                            pc,
                            vulnerability_type: "PredictableSecretGeneration".to_string(),
                            description: format!("HTLC hashlock at PC {} generated predictably from sequential values, enabling precomputation. Attack: secrets generated via counter or sequential nonce, attacker precomputes rainbow table of hash(i) for i in range, matches against HTLC hashlocks, claims funds. Real attack: payment channel uses sequential secrets hash(nonce++), attacker precomputes hash(0) through hash(1000000), matches payment hashes, claims without performing service. Example: atomic swap service generates secrets as hash(swapId) where swapId incremental, attacker computes hash(0) to hash(100000), monitors for HTLC creation, finds match, claims immediately. Missing: cryptographic randomness, unpredictable secret generation. Should implement: use CSPRNG for secret generation, include user randomness. Fix: generate secrets using secure random: secret = randomBytes(32), never use sequential or predictable values, implement rate limiting on HTLC claims to detect brute force attempts.", pc),
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
