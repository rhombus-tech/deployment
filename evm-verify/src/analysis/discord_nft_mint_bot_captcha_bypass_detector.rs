use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordBotVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct DiscordNftMintBotCaptchaBypassDetector {
    bytecode: Vec<u8>,
}

impl DiscordNftMintBotCaptchaBypassDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<DiscordBotVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_weak_captcha_implementation());
        vulnerabilities.extend(self.detect_bot_verification_bypass());
        vulnerabilities.extend(self.detect_rate_limit_evasion());

        vulnerabilities
    }

    fn detect_weak_captcha_implementation(&self) -> Vec<DiscordBotVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (whitelist storage)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_user_registration = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_verification = window.iter().any(|&b| b == 0x20); // KECCAK256
                
                if has_user_registration {
                    let has_cryptographic_proof = window.iter().filter(|&&b| b == 0x20).count() >= 3;
                    let has_external_verification = window.iter().any(|&b| b == 0xFA); // STATICCALL
                    
                    if !has_cryptographic_proof && !has_external_verification {
                        vulns.push(DiscordBotVulnerability {
                            pc,
                            vulnerability_type: "WeakCaptchaImplementation".to_string(),
                            description: format!(
                                "NFT mint whitelist verification at PC {} uses weak captcha. Attack: Discord NFT mint bots use captcha to prevent automated claiming, if captcha \
                                weak or client-side only, bots bypass and claim all NFTs. Common bypasses: (1) captcha verification done in Discord DM, attacker automates Discord \
                                API to solve, (2) captcha answer passed as parameter without server verification, (3) simple math/text captcha solved by OCR/AI. Example: bot sends \
                                'solve 2+3' captcha in DM, user replies '5', bot adds to whitelist - attacker scripts Discord bot to auto-solve math. Or: captcha uses predictable \
                                image patterns, AI model trained to solve. Results in: bots claim entire NFT supply, legitimate users can't mint, project reputation damage. Missing: \
                                cryptographic commit-reveal, hCaptcha/reCAPTCHA integration, rate limiting. Should use: cryptographic challenge (sign message with Discord account), \
                                integrate professional captcha service (hCaptcha), require Discord account age >30 days + activity score.",
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

    fn detect_bot_verification_bypass(&self) -> Vec<DiscordBotVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (verification check)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_mint_execution = window.iter().any(|&b| b == 0xF1); // CALL
                
                if has_mint_execution {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let verifies_discord_guild = pre_window.iter().filter(|&&b| b == 0x14).count() >= 2;
                    let checks_role_membership = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                    
                    if !verifies_discord_guild {
                        vulns.push(DiscordBotVulnerability {
                            pc,
                            vulnerability_type: "BotVerificationBypass".to_string(),
                            description: format!(
                                "Discord bot verification at PC {} can be bypassed. Attack: NFT projects use Discord role verification (must have specific role/server membership), \
                                if verification weak, bots create fake Discord accounts and bypass. Bypass methods: (1) bot creates Discord accounts en masse, joins server, gets role \
                                automatically, (2) verification only checks Discord user ID without confirming guild membership, (3) no check for account age/activity. Example: project \
                                requires 'Holder' role, bot creates 1000 Discord accounts, all join server and get auto-role from MEE6, all mint NFTs. Or: verification checks if user \
                                ID in whitelist but not if currently in server - user joins, gets whitelisted, leaves server, rejoins on alt accounts, mints multiple times. Missing: \
                                real-time guild membership verification, Discord OAuth scopes check, Sybil resistance. Should implement: verify user in guild at mint time via Discord API, \
                                check account creation date >90 days ago, require message history in server, limit 1 mint per Discord account + wallet address combination.",
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

    fn detect_rate_limit_evasion(&self) -> Vec<DiscordBotVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x42 { // TIMESTAMP (rate limiting)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_mint_action = window.iter().any(|&b| b == 0x55); // SSTORE
                
                if has_mint_action {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let tracks_per_address = pre_window.iter().any(|&b| b == 0x33); // CALLER
                    let enforces_cooldown = window.iter().filter(|&&b| b == 0x42).count() >= 2;
                    
                    if !tracks_per_address && !enforces_cooldown {
                        vulns.push(DiscordBotVulnerability {
                            pc,
                            vulnerability_type: "RateLimitEvasion".to_string(),
                            description: format!(
                                "Rate limiting at PC {} evadable via Sybil attacks. Attack: Discord bot implements per-account rate limits (1 mint per Discord user), but doesn't \
                                track wallet addresses, attacker creates multiple Discord accounts, mints multiple NFTs to same wallet. Or: rate limit based on IP, attacker uses \
                                proxies/VPN. Example: limit 1 mint per Discord account per hour, attacker creates 100 Discord accounts, mints 100 NFTs in parallel. Or: limit per \
                                wallet address but not per Discord account, attacker uses 100 wallets to claim full supply. Evasion techniques: residential proxy networks, Discord \
                                account farms, temporary email services for signups. Missing: combined address + Discord account tracking, proof of unique human, device fingerprinting. \
                                Should implement: track both (discordId, walletAddress) pairs, require wallet signature proving control, limit N mints per IP per day, implement \
                                proof-of-humanity (Worldcoin, Gitcoin Passport), monitor for suspicious patterns (100 accounts from same IP).",
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
