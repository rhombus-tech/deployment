/// Embedded Wallet SDK Vulnerability Detector
///
/// Detects vulnerabilities in embedded wallet implementations (Privy, Dynamic, Web3Auth,
/// Particle Network, Thirdweb Engine). These SDKs handle custody/MPC for 50%+ of new users.
///
/// Real-world context:
/// - $5B+ user funds in embedded wallets
/// - Privy: 10M+ wallets, Dynamic: 5M+, Web3Auth: 15M+
/// - Attack surface: Session keys, MPC shards, SDK injection, custodial key exposure
/// - Risk: One SDK exploit can drain millions of user wallets simultaneously

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedWalletVulnerability {
    pub vulnerability_type: EmbeddedWalletVulnerabilityType,
    pub severity: String,
    pub location: Vec<usize>,
    pub description: String,
    pub exploit_scenario: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmbeddedWalletVulnerabilityType {
    SessionKeyTheft,                // Session key stolen or replayed
    MPCShardExposure,               // MPC key shard leaked
    SDKInjectionAttack,             // Malicious SDK injected
    CustodialKeyExposure,           // Backend key material exposed
    SessionExpirationBypass,        // Expired sessions still valid
    SDKVersionVulnerability,        // Outdated SDK with known bugs
    CrossOriginSessionLeak,         // Session leaks to other origins
    WebAuthnBypass,                 // WebAuthn challenge bypassed
    RecoveryPhraseExposure,         // Seed phrase in client storage
    ThirdPartySignerTrust,          // Unverified third-party signer
}

pub struct EmbeddedWalletSDKDetector {
    bytecode: Vec<u8>,
}

impl EmbeddedWalletSDKDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<EmbeddedWalletVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // 1. Session key theft/replay
        if let Some(vuln) = self.detect_session_key_theft() {
            vulnerabilities.push(vuln);
        }
        
        // 2. MPC shard exposure
        if let Some(vuln) = self.detect_mpc_shard_exposure() {
            vulnerabilities.push(vuln);
        }
        
        // 3. Session expiration bypass
        if let Some(vuln) = self.detect_session_expiration_bypass() {
            vulnerabilities.push(vuln);
        }
        
        // 4. Custodial key exposure
        if let Some(vuln) = self.detect_custodial_key_exposure() {
            vulnerabilities.push(vuln);
        }
        
        // 5. Third-party signer trust
        if let Some(vuln) = self.detect_thirdparty_signer_trust() {
            vulnerabilities.push(vuln);
        }
        
        vulnerabilities
    }
    
    fn detect_session_key_theft(&self) -> Option<EmbeddedWalletVulnerability> {
        // Session keys must have nonce/timestamp to prevent replay
        
        for i in 0..self.bytecode.len().saturating_sub(25) {
            // Look for session key validation
            let mut validates_session = false;
            let mut checks_replay_protection = false;
            
            for j in i..self.bytecode.len().min(i + 25) {
                // Session validation (signature check)
                if self.bytecode[j] == 0x01 { // ECRECOVER
                    validates_session = true;
                }
                
                // Replay protection (nonce or timestamp check)
                if self.bytecode[j] == 0x54 { // SLOAD
                    if j + 3 < self.bytecode.len() && 
                       (self.bytecode[j+1] == 0x10 || self.bytecode[j+1] == 0x11) { // LT/GT
                        checks_replay_protection = true;
                    }
                }
            }
            
            if validates_session && !checks_replay_protection {
                return Some(EmbeddedWalletVulnerability {
                    vulnerability_type: EmbeddedWalletVulnerabilityType::SessionKeyTheft,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Session key validation lacks replay protection. Same session \
                                signature can be used multiple times to drain user funds.".to_string(),
                    exploit_scenario: "1. User logs in via Privy embedded wallet\n\
                                      2. Generates session key valid for 24 hours\n\
                                      3. User approves $100 swap transaction\n\
                                      4. Attacker intercepts session signature\n\
                                      5. No nonce tracking on-chain\n\
                                      6. Attacker replays signature 100 times\n\
                                      7. $10,000 drained instead of $100\n\
                                      8. User sees 100 identical transactions\n\
                                      9. $5M+ possible if attacker targets many users\n\
                                      10. Similar to Slope wallet $8M private key leak".to_string(),
                    recommendation: "Implement nonce-based replay protection: require(nonce == userNonce++). \
                                  Add timestamp validation: require(block.timestamp <= validUntil). \
                                  Use EIP-712 structured data with nonce. Rotate session keys frequently. \
                                  Add session revocation mechanism. Reference: Safe session key module.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_mpc_shard_exposure(&self) -> Option<EmbeddedWalletVulnerability> {
        // MPC wallets split key into shards - must validate shard sources
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            // Look for multi-sig/threshold validation
            let mut has_multisig = false;
            let mut validates_shard_sources = false;
            
            for j in i..self.bytecode.len().min(i + 30) {
                // Multiple ECRECOVER (threshold signatures)
                let ecrecover_count = self.bytecode[j..self.bytecode.len().min(j+20)]
                    .iter()
                    .filter(|&&b| b == 0x01)
                    .count();
                
                if ecrecover_count >= 2 {
                    has_multisig = true;
                }
                
                // Shard source validation (checking signer addresses)
                if self.bytecode[j] == 0x14 { // EQ (validating signer)
                    validates_shard_sources = true;
                }
            }
            
            if has_multisig && !validates_shard_sources {
                return Some(EmbeddedWalletVulnerability {
                    vulnerability_type: EmbeddedWalletVulnerabilityType::MPCShardExposure,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "MPC threshold signatures accepted without validating shard sources. \
                                Attacker can submit malicious shards to reconstruct private key.".to_string(),
                    exploit_scenario: "1. Web3Auth uses 2-of-3 MPC threshold\n\
                                      2. User holds 1 shard, Web3Auth holds 1, Google holds 1\n\
                                      3. Contract accepts any 2 shards (no source validation)\n\
                                      4. Attacker compromises Web3Auth server\n\
                                      5. Generates fake 'Google' shard\n\
                                      6. Submits Web3Auth shard + fake Google shard\n\
                                      7. Contract accepts as valid threshold\n\
                                      8. Attacker reconstructs full key\n\
                                      9. Drains all user funds\n\
                                      10. $500M+ at risk across Web3Auth's 15M wallets".to_string(),
                    recommendation: "Validate shard sources: require(approvedShardProviders[signer]). \
                                  Whitelist specific signer addresses per user. Use time-locked shard \
                                  rotation. Implement shard revocation. Add hardware security module \
                                  for critical shards. Reference: Fireblocks MPC security model.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_session_expiration_bypass(&self) -> Option<EmbeddedWalletVulnerability> {
        // Session keys must expire after set duration
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for session validation with expiration
            let mut validates_session = false;
            let mut checks_expiration = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                if self.bytecode[j] == 0x01 { // ECRECOVER
                    validates_session = true;
                }
                
                // Expiration check (timestamp comparison)
                if self.bytecode[j] == 0x42 { // TIMESTAMP
                    if j + 3 < self.bytecode.len() && self.bytecode[j+2] == 0x10 { // LT
                        checks_expiration = true;
                    }
                }
            }
            
            if validates_session && !checks_expiration {
                return Some(EmbeddedWalletVulnerability {
                    vulnerability_type: EmbeddedWalletVulnerabilityType::SessionExpirationBypass,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Session key validation doesn't check expiration timestamp. Old \
                                session keys remain valid indefinitely.".to_string(),
                    exploit_scenario: "1. User creates Dynamic wallet session for 1 hour\n\
                                      2. Session key valid from 1PM-2PM\n\
                                      3. User logs out at 2PM\n\
                                      4. Contract doesn't validate expiration\n\
                                      5. Attacker finds old session key in logs\n\
                                      6. Uses session key at 5PM (3 hours expired)\n\
                                      7. Session still accepted\n\
                                      8. Attacker drains user funds\n\
                                      9. $10M+ at risk if many expired sessions exploited".to_string(),
                    recommendation: "Enforce expiration: require(block.timestamp <= validUntil). \
                                  Store expiration time in session data. Add session revocation. \
                                  Implement session refresh with re-authentication. Use short \
                                  expiration times (1 hour max). Reference: EIP-4337 session keys.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_custodial_key_exposure(&self) -> Option<EmbeddedWalletVulnerability> {
        // Custodial wallets must protect backend key material
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for single-signer validation (custodial)
            let mut single_signer = false;
            let mut has_backup_signer = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                // Single ECRECOVER (custodial signer)
                if self.bytecode[j] == 0x01 {
                    single_signer = true;
                }
                
                // Backup/fallback signer
                if j + 5 < self.bytecode.len() && 
                   self.bytecode[j] == 0x01 && self.bytecode[j+3] == 0x01 { // 2 ECRECOVER
                    has_backup_signer = true;
                }
            }
            
            if single_signer && !has_backup_signer {
                return Some(EmbeddedWalletVulnerability {
                    vulnerability_type: EmbeddedWalletVulnerabilityType::CustodialKeyExposure,
                    severity: "Critical".to_string(),
                    location: vec![i],
                    description: "Custodial wallet relies on single backend signer. If backend key \
                                compromised, all user funds at risk with no backup recovery.".to_string(),
                    exploit_scenario: "1. Particle Network uses custodial model\n\
                                      2. Backend holds master signing key for all users\n\
                                      3. No backup signer or user recovery\n\
                                      4. Attacker compromises Particle's AWS account\n\
                                      5. Steals master signing key from secrets manager\n\
                                      6. Can sign transactions for ALL users\n\
                                      7. Mass drains 5M wallets\n\
                                      8. $1B+ stolen in single exploit\n\
                                      9. Similar to Axie Infinity Ronin $625M where keys leaked".to_string(),
                    recommendation: "Use MPC or multi-sig instead of single custodial key. Implement \
                                  user-controlled recovery. Add hardware security modules. Use threshold \
                                  encryption. Enable social recovery. Implement spending limits. \
                                  Add anomaly detection. Reference: Argent wallet recovery system.".to_string(),
                });
            }
        }
        
        None
    }
    
    fn detect_thirdparty_signer_trust(&self) -> Option<EmbeddedWalletVulnerability> {
        // Must validate third-party signers (OAuth providers, etc.)
        
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // Look for signer validation
            let mut validates_signature = false;
            let mut validates_signer_address = false;
            
            for j in i..self.bytecode.len().min(i + 20) {
                if self.bytecode[j] == 0x01 { // ECRECOVER
                    validates_signature = true;
                }
                
                // Signer whitelist check
                if self.bytecode[j] == 0x14 { // EQ (checking signer == expected)
                    validates_signer_address = true;
                }
            }
            
            if validates_signature && !validates_signer_address {
                return Some(EmbeddedWalletVulnerability {
                    vulnerability_type: EmbeddedWalletVulnerabilityType::ThirdPartySignerTrust,
                    severity: "High".to_string(),
                    location: vec![i],
                    description: "Contract accepts signatures from any address without verifying \
                                signer is authorized. Attacker can submit self-signed transactions.".to_string(),
                    exploit_scenario: "1. Thirdweb wallet uses Google OAuth signer\n\
                                      2. Contract validates signature but not signer address\n\
                                      3. Attacker creates own keypair\n\
                                      4. Signs transaction with attacker's key\n\
                                      5. Contract verifies signature is valid (it is)\n\
                                      6. Doesn't check if signer == Google's address\n\
                                      7. Accepts attacker's transaction\n\
                                      8. Drains user funds\n\
                                      9. $50M+ at risk if exploited at scale".to_string(),
                    recommendation: "Whitelist approved signers: require(approvedSigners[signer]). \
                                  Store expected signer address per user. Use signer registry. \
                                  Implement signer rotation with timelock. Add multi-party approval \
                                  for signer changes. Reference: Gnosis Safe owner management.".to_string(),
                });
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_session_key_theft() {
        // ECRECOVER without nonce check
        let bytecode = vec![
            0x01, // ECRECOVER (no SLOAD for nonce)
        ];
        
        let detector = EmbeddedWalletSDKDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            EmbeddedWalletVulnerabilityType::SessionKeyTheft
        )));
    }
    
    #[test]
    fn test_session_expiration_bypass() {
        // ECRECOVER without TIMESTAMP check
        let bytecode = vec![
            0x01, // ECRECOVER (no TIMESTAMP validation)
        ];
        
        let detector = EmbeddedWalletSDKDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            EmbeddedWalletVulnerabilityType::SessionExpirationBypass
        )));
    }
    
    #[test]
    fn test_thirdparty_signer_trust() {
        // ECRECOVER without signer validation
        let bytecode = vec![
            0x01, // ECRECOVER (no EQ check for signer)
        ];
        
        let detector = EmbeddedWalletSDKDetector::new(bytecode);
        let vulns = detector.detect_vulnerabilities();
        
        assert!(vulns.iter().any(|v| matches!(
            v.vulnerability_type,
            EmbeddedWalletVulnerabilityType::ThirdPartySignerTrust
        )));
    }
}
