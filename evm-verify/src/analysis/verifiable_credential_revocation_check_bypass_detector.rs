use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredentialRevocationVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct VerifiableCredentialRevocationCheckBypassDetector {
    bytecode: Vec<u8>,
}

impl VerifiableCredentialRevocationCheckBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<VerifiableCredentialRevocationVulnerability> {
        let mut vulnerabilities = Vec::new();
        vulnerabilities.extend(self.detect_missing_revocation_check());
        vulnerabilities.extend(self.detect_stale_revocation_list());
        vulnerabilities.extend(self.detect_revocation_status_caching());
        vulnerabilities
    }

    fn detect_missing_revocation_check(&self) -> Vec<VerifiableCredentialRevocationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x14 { // EQ (credential verification)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let verifies_signature = self.bytecode[start..pc].iter().filter(|&&b| b == 0x20).count() >= 2;
                if verifies_signature {
                    let window_end = (pc + 100).min(self.bytecode.len());
                    let checks_revocation = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x54).count() >= 2;
                    if !checks_revocation {
                        vulns.push(VerifiableCredentialRevocationVulnerability {
                            pc,
                            vulnerability_type: "MissingRevocationCheck".to_string(),
                            description: format!("Credential verification at PC {} doesn't check revocation status, accepting revoked credentials. Attack: verifiable credential cryptographically valid but revoked by issuer, contract verifies signature only, revoked credential accepted, unauthorized access granted. Real attack: employee credential revoked after termination, credential signature still valid, contract checks only signature not revocation list, ex-employee accesses system. Example: university degree credential holder expelled, degree revoked, DApp verifies degree signature, grants 'verified graduate' status, revoked credential accepted. Missing: revocation registry check, revocation list query. Should implement: query revocation registry before accepting credential. Fix: check credential ID against on-chain revocation registry (StatusList2021), verify credential not in revocation accumulator, implement real-time revocation check via oracle or on-chain list, reject if revoked.", pc),
                            confidence: 0.85,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_stale_revocation_list(&self) -> Vec<VerifiableCredentialRevocationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x54 { // SLOAD (revocation list read)
                let window_end = (pc + 100).min(self.bytecode.len());
                let used_in_verification = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x14).count() >= 1;
                if used_in_verification {
                    let checks_freshness = self.bytecode[pc..window_end].iter().filter(|&&b| b == 0x42).count() >= 1;
                    if !checks_freshness {
                        vulns.push(VerifiableCredentialRevocationVulnerability {
                            pc,
                            vulnerability_type: "StaleRevocationList".to_string(),
                            description: format!("Revocation list at PC {} used without freshness check, accepting recently revoked credentials. Attack: credential revoked but revocation list not updated on-chain, contract uses stale list, recently revoked credential appears valid, security window exploited. Real vulnerability: revocation list updated daily, credential revoked at 9am, update happens 6pm, 9-hour window where revoked credential accepted. Example: credit card credential revoked for fraud, merchant contract checks yesterday's revocation list, fraudulent transaction approved before list updates. Missing: revocation list timestamp validation, update frequency guarantee. Should implement: require revocation list updated within threshold (e.g., 1 hour). Fix: store revocation list timestamp, require block.timestamp - listTimestamp < MAX_AGE, implement push-based revocation updates instead of pull, use accumulator-based revocation for instant on-chain updates.", pc),
                            confidence: 0.82,
                        });
                    }
                }
            }
            pc += 1;
            if opcode >= 0x60 && opcode <= 0x7F { pc += (opcode - 0x5F) as usize; }
        }
        vulns
    }

    fn detect_revocation_status_caching(&self) -> Vec<VerifiableCredentialRevocationVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;
        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];
            if opcode == 0x55 { // SSTORE (caching revocation status)
                let start = if pc > 100 { pc - 100 } else { 0 };
                let caches_revocation_status = self.bytecode[start..pc].iter().filter(|&&b| b == 0x54).count() >= 2;
                if caches_revocation_status {
                    let has_expiry = self.bytecode[start..pc].iter().filter(|&&b| b == 0x42).count() >= 1;
                    if !has_expiry {
                        vulns.push(VerifiableCredentialRevocationVulnerability {
                            pc,
                            vulnerability_type: "RevocationStatusCaching".to_string(),
                            description: format!("Revocation status caching at PC {} has no expiry, using indefinitely stale data. Attack: contract caches 'credential X not revoked', never refreshes, credential later revoked, cached status never updated, revoked credential permanently accepted. Real attack: access control caches employee credential status as valid, employee fired and credential revoked, cache never expires, ex-employee retains access indefinitely. Example: DApp caches credential verification results for gas efficiency, credential revoked week later, DApp still uses week-old cached 'valid' status, grants unauthorized access. Missing: cache expiration, cache invalidation on revocation events. Should implement: cache TTL, event-driven cache invalidation. Fix: add cache expiry timestamp, require re-check if block.timestamp > cacheTime + TTL, subscribe to revocation events to invalidate cache immediately, implement max cache TTL of 1 hour for security-critical credentials.", pc),
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
