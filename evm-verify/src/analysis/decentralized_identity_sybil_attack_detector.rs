use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecentralizedIdentitySybilVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct DecentralizedIdentitySybilAttackDetector {
    bytecode: Vec<u8>,
}

impl DecentralizedIdentitySybilAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<DecentralizedIdentitySybilVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_unlimited_identity_creation());
        vulnerabilities.extend(self.detect_missing_uniqueness_verification());
        vulnerabilities.extend(self.detect_weak_attestation_requirements());
        vulnerabilities
    }

    fn detect_unlimited_identity_creation(&self) -> Vec<DecentralizedIdentitySybilVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (identity creation)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let creates_identity = self.bytecode[start..pc].iter().filter(|&&b| b == 0x20).count() >= 1;
                if creates_identity {
                    let has_rate_limit = self.bytecode[start..pc].iter().filter(|&&b| b == 0x42).count() >= 1;
                    let has_cost = self.bytecode[start..pc].iter().any(|&b| b == 0x34);
                    if !has_rate_limit && !has_cost {
                        vulns.push(DecentralizedIdentitySybilVulnerability {
                            pc,
                            vulnerability_type: "UnlimitedIdentityCreation".to_string(),
                            description: format!("Identity creation at PC {} has no rate limiting or cost, enabling Sybil attacks. Attack: DID system allows free unlimited identity creation, attacker generates thousands of DIDs, gains disproportionate voting power, manipulates governance. Real attack: DAO uses DID for voting, one-DID-one-vote, attacker creates 10,000 DIDs from single wallet, controls 99% of votes, passes malicious proposals. Example: reputation system grants privileges based on DID count, attacker creates 1000 DIDs, gains maximum reputation instantly, bypasses merit-based system. Missing: identity creation cost, rate limiting, proof of uniqueness. Should implement: require payment or stake for identity creation, rate limit per address. Fix: charge fee for DID creation (e.g., 0.1 ETH), implement cooldown period (1 DID per address per month), require proof-of-humanity verification, use quadratic voting instead of linear.", pc),
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

    fn detect_missing_uniqueness_verification(&self) -> Vec<DecentralizedIdentitySybilVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x20 { // SHA3 (DID generation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let generates_did = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 1;
                if generates_did {
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let verifies_uniqueness = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x54).count() >= 2;
                    if !verifies_uniqueness {
                        vulns.push(DecentralizedIdentitySybilVulnerability {
                            pc,
                            vulnerability_type: "MissingUniquenessVerification".to_string(),
                            description: format!("DID generation at PC {} doesn't verify human uniqueness, allowing multiple identities per person. Attack: DID creation based only on wallet signature, one person creates many wallets, generates unique DID for each, system cannot detect they're same human. Real vulnerability: airdrop distributes tokens to unique DIDs, attacker creates 100 DIDs, claims 100x allocation, unfair distribution. Example: UBI protocol gives 1000 tokens per DID monthly, attacker with 50 DIDs receives 50,000 tokens, legitimate users get 1000, economic model broken. Missing: proof-of-humanity, biometric verification, social graph analysis. Should implement: integrate proof-of-humanity (Worldcoin, BrightID), require attestations. Fix: require proof-of-unique-human before DID activation, implement social graph verification (DIDs must be connected to existing verified DIDs), use privacy-preserving biometric checks, implement reputation decay to devalue Sybil identities.", pc),
                            confidence: 0.86,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_weak_attestation_requirements(&self) -> Vec<DecentralizedIdentitySybilVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (attestation storage)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let stores_attestation = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 2;
                if stores_attestation {
                    let requires_multiple = self.bytecode[start..pc].iter().filter(|&&b| b == 0x10).count() >= 2;
                    if !requires_multiple {
                        vulns.push(DecentralizedIdentitySybilVulnerability {
                            pc,
                            vulnerability_type: "WeakAttestationRequirements".to_string(),
                            description: format!("Attestation storage at PC {} accepts single attestation, enabling Sybil verification collusion. Attack: DID requires only one attestation for verification, attacker controls both DID and attester, self-attests all Sybil identities, verification bypassed. Real attack: identity verification requires 1 attestation, attacker creates attester DID, uses it to verify 1000 Sybil DIDs, all appear legitimate. Example: voting system requires verified DID, verification = 1 attestation, attacker's attester verifies all their Sybils, controls election. Missing: multiple independent attestations, attester reputation, stake requirements. Should implement: require N attestations from diverse attesters (N >= 3). Fix: require minimum 3 attestations from independent attesters, implement attester reputation scoring, slash attesters for verifying Sybils, use web-of-trust where attesters must themselves be highly attested, prevent attestation loops.", pc),
                            confidence: 0.80,
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
