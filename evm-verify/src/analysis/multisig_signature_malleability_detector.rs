use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigSignatureMalleabilityVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct MultisigSignatureMalleabilityDetector {
    bytecode: Vec<u8>,
}

impl MultisigSignatureMalleabilityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<MultisigSignatureMalleabilityVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_missing_s_value_check());
        vulnerabilities.extend(self.detect_signature_replay_via_malleability());
        vulnerabilities.extend(self.detect_duplicate_signer_allowance());
        vulnerabilities
    }

    fn detect_missing_s_value_check(&self) -> Vec<MultisigSignatureMalleabilityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x01 { // ecrecover precompile call location
                let start = if pc > 120 { pc - 120 } else { 0 };
                let has_ecrecover_pattern = self.bytecode[start..pc].iter().filter(|&&b| matches!(b, 0x60 | 0xFA)).count() >= 2;
                if has_ecrecover_pattern {
                    let validates_s_range = self.bytecode[start..pc].iter().filter(|&&b| b == 0x10).count() >= 2;
                    if !validates_s_range {
                        vulns.push(MultisigSignatureMalleabilityVulnerability {
                            pc,
                            vulnerability_type: "MissingSValueCheck".to_string(),
                            description: format!("ECDSA signature verification at PC {} doesn't validate s value range, enabling signature malleability. Attack: ECDSA signature (r, s) has malleable counterpart (r, -s mod n), both valid for same message, attacker flips signature, bypasses duplicate signature checks, reuses signer approval. Real attack: multi-sig requires 3 unique signatures, attacker obtains valid (r, s) from Signer1, creates (r, n-s), both recover to Signer1 address, but treated as different signatures, counts as 2 approvals. Example: executeTransaction checks signatureHash not used, attacker flips s value, new hash, replay protection bypassed, transaction executes twice with same signer set. Missing: require(s <= secp256k1n/2). Should implement: uint256 s = uint256(signature[32:64]); require(s <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0). Fix: validate s in lower half of curve order, reject signatures with s > n/2, use EIP-2 non-malleable signatures.", pc),
                            confidence: 0.88,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_signature_replay_via_malleability(&self) -> Vec<MultisigSignatureMalleabilityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x20 { // SHA3 (signature hash)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let hashes_signature = self.bytecode[start..pc].iter().filter(|&&b| b == 0x35).count() >= 3;
                if hashes_signature {
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let checks_used_sigs = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x54).count() >= 1;
                    let normalizes_signature = self.bytecode[start..pc].iter().filter(|&&b| b == 0x10).count() >= 1;
                    if checks_used_sigs && !normalizes_signature {
                        vulns.push(MultisigSignatureMalleabilityVulnerability {
                            pc,
                            vulnerability_type: "SignatureReplayViaMalleability".to_string(),
                            description: format!("Signature replay protection at PC {} defeated by malleability. Attack: multi-sig stores used signature hashes, malleable signatures have different hashes, attacker flips signature, hash changes, replay check passes, transaction executes multiple times. Real attack: multi-sig executeWithSignatures() stores usedHashes[keccak256(signatures)] = true, attacker obtains signatures (r1,s1), (r2,s2), (r3,s3), creates (r1,-s1), (r2,-s2), (r3,-s3), different hash, executes again draining funds. Example: withdrawal signed by 3-of-5 multi-sig, transfers 100 ETH, attacker malleable-flips all signatures, new hash, executes second time, 200 ETH withdrawn with same signing set. Missing: canonical signature enforcement, signer-based nonce. Should implement: normalize signatures before hashing, or use signer addresses in replay protection. Fix: replace usedHashes[hash(signatures)] with mapping(address => nonce), increment nonce per signer, prevents malleability replay.", pc),
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

    fn detect_duplicate_signer_allowance(&self) -> Vec<MultisigSignatureMalleabilityVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x01 { // ecrecover result
                let window_end = (pc + 120).min(self.bytecode.len());
                let counts_signatures = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x01).count() >= 2;
                if counts_signatures {
                    let deduplicates = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x14).count() >= 3;
                    if !deduplicates {
                        vulns.push(MultisigSignatureMalleabilityVulnerability {
                            pc,
                            vulnerability_type: "DuplicateSignerAllowance".to_string(),
                            description: format!("Signature verification at PC {} doesn't prevent duplicate signers, enabling threshold bypass. Attack: multi-sig requires M-of-N signatures, doesn't deduplicate recovered addresses, attacker provides same signature M times (or malleable variants), threshold check passes with single signer. Real attack: 3-of-5 multi-sig, attacker obtains one valid signature from Signer1, creates (sig1, sig1_malleable1, sig1_malleable2), all recover to Signer1, threshold check: recoveredSigners.length >= 3, passes, executes with only one actual signer. Example: Gnosis Safe style verification loops through signatures, each ecrecover succeeds returning same address, validSignatures++ three times, threshold met, transaction executes defeating multi-sig purpose. Missing: duplicate signer detection, unique address requirement. Should implement: for each recovered address, require(seenSigners[addr] == false); seenSigners[addr] = true. Fix: maintain set of recovered addresses, reject if address appears twice, ensures M unique signers required.", pc),
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
}
