use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PenumbraViewKeyVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct PenumbraViewKeyLeakageDetector {
    bytecode: Vec<u8>,
}

impl PenumbraViewKeyLeakageDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<PenumbraViewKeyVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_view_key_exposure_in_storage());
        vulnerabilities.extend(self.detect_diversifier_reuse_tracking());
        vulnerabilities.extend(self.detect_amount_decryption_side_channel());

        vulnerabilities
    }

    fn detect_view_key_exposure_in_storage(&self) -> Vec<PenumbraViewKeyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (key storage)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_key_material = window.iter().filter(|&&b| b == 0x35).count() >= 2; // CALLDATALOAD
                let has_encryption = window.iter().any(|&b| b == 0x20); // KECCAK256
                
                if has_key_material {
                    let has_proper_encryption = window.iter().filter(|&&b| b == 0x20).count() >= 3;
                    let has_access_control = window.iter().any(|&b| b == 0x33); // CALLER check
                    
                    if !has_proper_encryption {
                        vulns.push(PenumbraViewKeyVulnerability {
                            pc,
                            vulnerability_type: "ViewKeyExposureInStorage".to_string(),
                            description: format!(
                                "View key storage at PC {} may expose sensitive key material. Attack: Penumbra uses view keys for selective disclosure (allow auditor to view \
                                transactions without spending power), but if view keys stored on-chain unencrypted or weakly encrypted, adversary can: (1) read view keys from \
                                storage, (2) decrypt all past/future transactions visible to that key, (3) track all balances and transfers for that address. View key compromise \
                                less severe than spend key but still breaks privacy. Example: compliance system stores view keys in contract for regulatory reporting, hacker reads \
                                storage slot, decrypts all user transactions. Or: view key derivation uses weak randomness, attacker brute-forces key from on-chain data. Missing: \
                                proper key encryption (e.g., encrypt view key with user's master key), off-chain storage, hardware wallet protection. Should never store: raw view \
                                keys on-chain, use encrypted storage with strong KDF, or keep view keys entirely off-chain.",
                                pc
                            ),
                            confidence: 0.89,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_diversifier_reuse_tracking(&self) -> Vec<PenumbraViewKeyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (address derivation)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_diversifier = window.iter().filter(|&&b| b == 0x35).count() >= 1;
                
                if has_diversifier {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let enforces_unique_diversifier = window.iter().filter(|&&b| b == 0x54).count() >= 2; // SLOAD checks
                    let has_randomness_requirement = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    
                    if !enforces_unique_diversifier {
                        vulns.push(PenumbraViewKeyVulnerability {
                            pc,
                            vulnerability_type: "DiversifierReuseTracking".to_string(),
                            description: format!(
                                "Address diversifier generation at PC {} allows reuse enabling tracking. Attack: Penumbra uses diversified addresses (generate many addresses from \
                                single key using diversifier), but if diversifiers reused or predictable, breaks privacy. Adversary observes: address A_d1 receives 10 ETH, later \
                                address A_d1 sends 5 ETH, knows same owner despite different transactions. Or: diversifiers derived deterministically (d = counter++), adversary \
                                enumerates all addresses for victim's view key. Enables: address clustering (group all addresses for same user), transaction graph analysis, balance \
                                tracking across diversified addresses. Example: user generates addresses with diversifiers 0,1,2,3..., adversary computes all possible addresses, \
                                monitors blockchain for any activity. Missing: random diversifier generation, diversifier uniqueness enforcement, diversifier blinding. Should use: \
                                cryptographically random diversifiers, never reuse diversifiers, rotate diversifiers frequently.",
                                pc
                            ),
                            confidence: 0.85,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }

    fn detect_amount_decryption_side_channel(&self) -> Vec<PenumbraViewKeyVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x02 { // MUL (decryption operation)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_encrypted_amount = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                let has_decryption_key = window.iter().any(|&b| b == 0x35);
                
                if has_encrypted_amount && has_decryption_key {
                    let has_constant_time_ops = window.iter().filter(|&&b| b == 0x02).count() >= 3;
                    let avoids_conditional_paths = window.iter().filter(|&&b| b == 0x57).count() == 0; // No JUMPI
                    
                    if !avoids_conditional_paths {
                        vulns.push(PenumbraViewKeyVulnerability {
                            pc,
                            vulnerability_type: "AmountDecryptionSideChannel".to_string(),
                            description: format!(
                                "Amount decryption at PC {} vulnerable to side-channel leaks. Attack: Penumbra encrypts transaction amounts, decryption with view key should be \
                                constant-time, but implementation may leak information via: (1) timing differences based on decrypted amount value, (2) gas usage varying with \
                                amount, (3) conditional branches based on decrypted amount, (4) error messages revealing amount properties. Example: decryption takes longer for \
                                large amounts due to range check, timing reveals approximate amount even without view key. Or: gas usage differs for zero vs non-zero amounts, \
                                adversary infers amount range from transaction cost. Also vulnerable to: cache timing attacks, speculative execution leaks, electromagnetic emanation. \
                                Missing: constant-time decryption, uniform gas costs, no value-dependent branches. Should implement: all operations constant-time regardless of \
                                decrypted value, pad gas usage to maximum, avoid early-exit optimizations, use blinding techniques.",
                                pc
                            ),
                            confidence: 0.83,
                        });
                    }
                }
            }

            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F {
                pc += (opcode - 0x5F) as usize;
            }
        }

        vulns
    }
}
