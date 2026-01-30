use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FireblocksMpcVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct FireblocksMpcWalletKeyRefreshDetector {
    bytecode: Vec<u8>,
}

impl FireblocksMpcWalletKeyRefreshDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<FireblocksMpcVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_incomplete_key_refresh());
        vulnerabilities.extend(self.detect_share_consistency_failure());
        vulnerabilities.extend(self.detect_refresh_timing_attack());

        vulnerabilities
    }

    fn detect_incomplete_key_refresh(&self) -> Vec<FireblocksMpcVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (key share update)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_share_commitment = window.iter().any(|&b| b == 0x20); // KECCAK256
                let has_verification = window.iter().any(|&b| b == 0xFA); // STATICCALL (proof check)
                
                if has_share_commitment {
                    let has_atomic_update = window.iter().filter(|&&b| b == 0x55).count() >= 3; // Multiple SSTORE
                    let has_rollback_mechanism = window.iter().any(|&b| b == 0xFD); // REVERT capability
                    
                    if !has_atomic_update {
                        vulns.push(FireblocksMpcVulnerability {
                            pc,
                            vulnerability_type: "IncompleteKeyRefresh".to_string(),
                            description: format!(
                                "MPC key refresh at PC {} lacks atomicity guarantees. Attack: MPC wallets use threshold signatures (t-of-n), key refresh protocol rotates shares \
                                while keeping same public key, if refresh not atomic: (1) some parties complete refresh, others don't, (2) inconsistent share sets exist, (3) can't \
                                reconstruct signing key with either old or new shares. Results in locked funds. Example: 3-of-5 MPC wallet refreshes, 3 parties update to new shares, \
                                2 parties transaction fails, now can't get 3 valid shares from either set. Or: attacker disrupts refresh for specific parties creating permanent \
                                deadlock. Missing: two-phase commit for refresh, rollback on partial failure, timeout recovery. Should implement: all parties commit to new shares \
                                before any apply, if any party fails revert all to old shares, maintain old shares until new shares proven functional.",
                                pc
                            ),
                            confidence: 0.87,
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

    fn detect_share_consistency_failure(&self) -> Vec<FireblocksMpcVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (share commitment)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_share_data = window.iter().filter(|&&b| b == 0x35).count() >= 2;
                
                if has_share_data {
                    let window_end = (pc + 80).min(self.bytecode.len());
                    let forward = &self.bytecode[pc..window_end];
                    
                    let verifies_share_consistency = forward.iter().filter(|&&b| b == 0x14).count() >= 3; // Multiple EQ
                    let checks_all_parties = window.iter().filter(|&&b| b == 0x54).count() >= 3;
                    
                    if !verifies_share_consistency {
                        vulns.push(FireblocksMpcVulnerability {
                            pc,
                            vulnerability_type: "ShareConsistencyFailure".to_string(),
                            description: format!(
                                "Share commitment verification at PC {} doesn't ensure consistency. Attack: in MPC refresh, each party generates new share, must verify all shares \
                                consistent (correspond to same secret), if verification weak, malicious party provides inconsistent share. Results in: shares don't reconstruct valid \
                                key, signature generation fails, funds stuck. Example: honest refresh should maintain f(x) = secret polynomial, attacker provides share from different \
                                polynomial f'(x), later signature combining uses inconsistent shares, produces invalid signature. Or: attacker causes share to be off by small value, \
                                signature generation succeeds in tests but fails for real transactions due to field arithmetic. Missing: VSS (Verifiable Secret Sharing), zero-knowledge \
                                proofs of correct refresh, pairwise consistency checks. Should use: Feldman VSS or Pedersen VSS with commitments, each party proves new share correct, \
                                test signing with new shares before committing.",
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

    fn detect_refresh_timing_attack(&self) -> Vec<FireblocksMpcVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP (refresh coordination)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_share_update = window.iter().any(|&b| b == 0x55); // SSTORE
                let has_multi_party_coordination = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                
                if has_share_update && has_multi_party_coordination {
                    let has_timeout_protection = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    let has_synchronization = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if !has_timeout_protection {
                        vulns.push(FireblocksMpcVulnerability {
                            pc,
                            vulnerability_type: "RefreshTimingAttack".to_string(),
                            description: format!(
                                "Key refresh timing at PC {} vulnerable to DoS and race conditions. Attack: MPC refresh requires synchronous participation from t parties, attacker \
                                can: (1) delay own participation causing timeout, forcing restart, (2) join late and disrupt refresh, (3) cause timing-based inconsistencies. Repeated \
                                disruption prevents refresh, if old shares compromised and can't refresh, attacker eventually gains threshold. Example: attacker controls 1-of-5 parties, \
                                repeatedly times out refresh protocol, other 4 parties can't complete refresh, after 6 months attacker compromises 2 more shares (now has 3-of-5), steals \
                                funds. Or: race condition where parties apply new shares at different times, transaction signed during transition uses mixed old/new shares, invalid \
                                signature. Missing: strict timeout enforcement, penalty for non-participation, refresh transaction blackout period. Should implement: parties must \
                                complete within timeout or refresh aborts entirely, penalize parties causing >N timeouts, pause all transactions during refresh window.",
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
