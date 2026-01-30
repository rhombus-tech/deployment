use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc5409AttestationVulnerability {
    pub vulnerability_type: String,
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: String,
}

pub struct Erc5409AttestationDetector {
    bytecode: Vec<u8>,
}

impl Erc5409AttestationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc5409AttestationVulnerability> {
        let mut vulnerabilities = Vec::new();

        // ERC-5409 defines on-chain attestations
        // Detect attestation forgery
        if let Some(location) = self.has_attestation_forgery_risk() {
            vulnerabilities.push(Erc5409AttestationVulnerability {
                vulnerability_type: "ERC-5409 Attestation Forgery".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Attestations can be created without signature verification. Unauthorized parties could forge attestations. Implement ECDSA signature verification for all attestations.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect attestation revocation without authority
        if let Some(location) = self.has_unauthorized_revocation() {
            vulnerabilities.push(Erc5409AttestationVulnerability {
                vulnerability_type: "ERC-5409 Unauthorized Attestation Revocation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Attestations can be revoked by non-attesters. Only original attester should revoke their attestation. Implement attester authorization check.".to_string(),
                confidence: "High".to_string(),
            });
        }

        // Detect missing timestamp validation
        if let Some(location) = self.has_missing_timestamp_validation() {
            vulnerabilities.push(Erc5409AttestationVulnerability {
                vulnerability_type: "ERC-5409 Missing Timestamp Validation".to_string(),
                location,
                severity: "High".to_string(),
                description: "Attestations accepted without timestamp validation. Expired or future-dated attestations could be accepted. Validate timestamps against block.timestamp with reasonable bounds.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        // Detect attestation replay
        if let Some(location) = self.has_attestation_replay_risk() {
            vulnerabilities.push(Erc5409AttestationVulnerability {
                vulnerability_type: "ERC-5409 Attestation Replay Attack".to_string(),
                location,
                severity: "Critical".to_string(),
                description: "Attestations lack nonce or unique identifier. Same attestation signature could be replayed multiple times. Include nonce in attestation data and track used attestations.".to_string(),
                confidence: "Medium".to_string(),
            });
        }

        vulnerabilities
    }

    fn has_attestation_forgery_risk(&self) -> Option<usize> {
        // Pattern: Attestation storage (SSTORE) without signature verification
        for i in 0..self.bytecode.len().saturating_sub(35) {
            if self.bytecode[i] == 0x55 { // SSTORE (storing attestation)
                // Look for ECRECOVER (signature verification)
                let mut has_sig_verification = false;
                
                for j in i.saturating_sub(50)..i {
                    if self.bytecode[j] == 0x01 { // ECRECOVER precompile address
                        // Check if CALL or STATICCALL to ecrecover
                        for k in j+1..(j+20).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0xf1 || self.bytecode[k] == 0xfa { // CALL/STATICCALL
                                has_sig_verification = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_sig_verification {
                    // Verify this looks like attestation (multiple data fields)
                    let mut data_fields = 0;
                    for j in i.saturating_sub(25)..i {
                        if self.bytecode[j] == 0x35 { // CALLDATALOAD
                            data_fields += 1;
                        }
                    }
                    if data_fields >= 3 { // Typical attestation has multiple fields
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_unauthorized_revocation(&self) -> Option<usize> {
        // Pattern: Attestation deletion/revocation without attester check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 { // SSTORE (revocation)
                // Check if setting to zero/invalid (revocation pattern)
                let mut is_revocation = false;
                for j in i.saturating_sub(10)..i {
                    if self.bytecode[j] == 0x60 { // PUSH1
                        if j + 1 < self.bytecode.len() && self.bytecode[j + 1] == 0 {
                            is_revocation = true;
                        }
                    }
                }
                
                if is_revocation {
                    // Check for attester authorization
                    let mut has_attester_check = false;
                    
                    for j in i.saturating_sub(35)..i {
                        // Look for stored attester comparison with CALLER
                        if self.bytecode[j] == 0x54 { // SLOAD (original attester)
                            for k in j+1..(j+15).min(self.bytecode.len()).min(self.bytecode.len()) {
                                if self.bytecode[k] == 0x33 { // CALLER
                                    for m in k+1..(k+5).min(self.bytecode.len()) {
                                        if self.bytecode[m] == 0x14 { // EQ
                                            has_attester_check = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    
                    if !has_attester_check {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn has_missing_timestamp_validation(&self) -> Option<usize> {
        // Pattern: Attestation storage without timestamp bounds check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x55 { // SSTORE (attestation)
                // Check for timestamp validation
                let mut has_timestamp_validation = false;
                
                for j in i.saturating_sub(30)..i {
                    if self.bytecode[j] == 0x42 { // TIMESTAMP
                        // Look for comparison operations
                        for k in j+1..(j+10).min(self.bytecode.len()).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x10 || self.bytecode[k] == 0x11 { // LT/GT
                                has_timestamp_validation = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_timestamp_validation {
                    // Verify this is attestation with timestamp field
                    for j in i.saturating_sub(20)..i {
                        if self.bytecode[j] == 0x35 { // CALLDATALOAD (timestamp field)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }

    fn has_attestation_replay_risk(&self) -> Option<usize> {
        // Pattern: Attestation processing without nonce tracking
        for i in 0..self.bytecode.len().saturating_sub(40) {
            // Look for signature verification
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xfa { // CALL/STATICCALL (to ecrecover)
                // Check if nonce is tracked (SLOAD of used nonces)
                let mut has_nonce_tracking = false;
                
                for j in i+1..(i+45).min(self.bytecode.len()) {
                    // Look for nonce storage check
                    if self.bytecode[j] == 0x54 { // SLOAD (checking used nonce)
                        for k in j+1..(j+10).min(self.bytecode.len()) {
                            if self.bytecode[k] == 0x15 { // ISZERO (nonce not used)
                                has_nonce_tracking = true;
                                break;
                            }
                        }
                    }
                }
                
                if !has_nonce_tracking {
                    // Check if attestation is stored after verification
                    for j in i+1..(i+35).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x55 { // SSTORE (storing attestation)
                            return Some(i);
                        }
                    }
                }
            }
        }
        None
    }
}
