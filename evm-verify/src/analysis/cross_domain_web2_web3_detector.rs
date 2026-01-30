use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CrossDomainVulnerability {
    OAuthIntegrationExploit { description: String, location: usize, confidence: f32 },
    EmailSMSVerificationBypass { description: String, location: usize, confidence: f32 },
    DNSENSAttack { description: String, location: usize, confidence: f32 },
}

pub struct CrossDomainWeb2Web3Detector {
    bytecode: Vec<u8>,
}

impl CrossDomainWeb2Web3Detector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }
    
    pub fn detect_vulnerabilities(&self) -> Vec<CrossDomainVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Cross-domain Web2↔Web3: OAuth, email verification, DNS attacks
        
        for i in 0..self.bytecode.len().saturating_sub(85) {
            let section = &self.bytecode[i..std::cmp::min(i + 85, self.bytecode.len())];
            
            // Pattern 1: External signature verification (OAuth-style)
            let has_external_verify = section.windows(15).any(|w| {
                w.contains(&0xFA) && // STATICCALL (verify signature)
                w.contains(&0x3D) && // RETURNDATASIZE
                w.contains(&0x14)    // EQ (check result)
            });
            
            if has_external_verify {
                vulnerabilities.push(CrossDomainVulnerability::OAuthIntegrationExploit {
                    description: format!("OAuth integration exploit at PC {}. Contract verifies Web2 credentials via external call. Attack: 1) Twitter OAuth: Attacker compromises OAuth provider → issues fake tokens → gains access. 2) Google login: Attacker tricks OAuth flow → associates attacker's Web2 ID with victim's wallet. 3) Discord bot: Bot has admin access → attacker compromises bot → controls all Web3 permissions. 4) GitHub Actions: Uses repo secrets → attacker forks repo → steals secrets → accesses protocol admin. Example: Slope wallet leaked private keys via Google Analytics. Fix: Don't trust Web2 auth for Web3 security, use ZK proofs for identity (Sismo, Polygon ID), or hybrid: require both Web2 + wallet signature.", i),
                    location: i,
                    confidence: 0.82,
                });
            }
            
            // Pattern 2: Off-chain verification without timestamp/nonce
            let has_offchain_data = section.windows(12).any(|w| {
                w.contains(&0x20) && // SHA3 (hash message)
                w.contains(&0x01)    // ECRECOVER (verify sig)
            });
            
            let no_timestamp = !section.windows(8).any(|w| {
                w.contains(&0x42) && // TIMESTAMP
                w.contains(&0x10)    // LT (check expiry)
            });
            
            if has_offchain_data && no_timestamp {
                vulnerabilities.push(CrossDomainVulnerability::EmailSMSVerificationBypass {
                    description: format!("Email/SMS verification bypass at PC {}. Off-chain verification without replay protection. Attack: 1) Protocol sends verification email with code → user verifies → attacker reuses same signature → verifies again. 2) SMS 2FA: Code sent once → attacker intercepts → uses forever. 3) KYC provider: Issues credential → user passes KYC → sells credential → many wallets use same KYC. 4) Worldcoin: Proof-of-humanity verified once → can be replayed. Example: Attacker intercepts SMS code, uses it multiple times. Fix: Add timestamp + deadline to signatures, include nonce (use once), or bind verification to specific wallet address that cannot transfer.", i),
                    location: i,
                    confidence: 0.85,
                });
            }
            
            // Pattern 3: String-based identification (ENS-style)
            let has_string_lookup = section.windows(12).any(|w| {
                w.contains(&0x20) && // SHA3 (hash string)
                w.contains(&0x54) && // SLOAD (lookup)
                w.contains(&0x14)    // EQ (match)
            });
            
            if has_string_lookup {
                vulnerabilities.push(CrossDomainVulnerability::DNSENSAttack {
                    description: format!("DNS/ENS attack at PC {}. String-based resolution vulnerable to homograph attacks. Attack: 1) ENS: Register 'vitalik.eth' (with invisible Unicode) → looks identical → users send funds to fake address. 2) DNS: Control DNS server → redirect ens-domain.com to attacker site → users sign malicious txs. 3) IPFS: Upload malicious metadata to IPFS → NFT points to Qm... hash → users see fake NFT. 4) Unstoppable Domains: Register similar domain → phishing. Real: $50M+ via ENS/DNS phishing. Mitigation: Validate ENS name contains only ASCII, verify forward+reverse resolution matches, show Ethereum address alongside ENS name, or use subgraph to check registration history.", i),
                    location: i,
                    confidence: 0.80,
                });
            }
        }
        
        vulnerabilities
    }
}
