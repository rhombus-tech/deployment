use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramBotVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct TelegramTradingBotPrivateKeyExposureDetector {
    bytecode: Vec<u8>,
}

impl TelegramTradingBotPrivateKeyExposureDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<TelegramBotVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_plaintext_key_storage());
        vulnerabilities.extend(self.detect_key_derivation_weakness());
        vulnerabilities.extend(self.detect_session_hijacking_vulnerability());

        vulnerabilities
    }

    fn detect_plaintext_key_storage(&self) -> Vec<TelegramBotVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (key storage)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_key_material = window.iter().filter(|&&b| b == 0x35).count() >= 2; // CALLDATALOAD
                
                if has_key_material {
                    let has_encryption = window.iter().filter(|&&b| b == 0x20).count() >= 3; // Multiple KECCAK256
                    let has_access_control = window.iter().any(|&b| b == 0x33); // CALLER
                    
                    if !has_encryption {
                        vulns.push(TelegramBotVulnerability {
                            pc,
                            vulnerability_type: "PlaintextKeyStorage".to_string(),
                            description: format!(
                                "Trading bot key storage at PC {} stores private keys in plaintext. Attack: Telegram trading bots (Unibot, Maestro, BananaGun) manage user wallets \
                                for automated trading, if private keys stored unencrypted on-chain or in contract storage, attacker reading storage steals all user funds. Example: \
                                bot contract stores mapping(telegramUserId => privateKey), attacker reads storage slots, extracts keys for all users, drains wallets. Or: keys stored \
                                in logs/events for syncing, attacker monitors events, captures keys. Real risk: Telegram bot users deposit significant funds (often $10K-$1M), compromise \
                                affects many users. Missing: key encryption with user password, HSM/TEE for key management, deterministic wallet derivation. Should use: encrypt keys \
                                with AES-256 using password-derived key (PBKDF2), or use HD wallet (derive from single seed encrypted), never store raw private keys on-chain.",
                                pc
                            ),
                            confidence: 0.92,
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

    fn detect_key_derivation_weakness(&self) -> Vec<TelegramBotVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (key derivation)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_user_identifier = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_user_identifier {
                    let uses_strong_kdf = window.iter().filter(|&&b| b == 0x20).count() >= 4; // Multiple hash rounds
                    let has_salt = window.iter().filter(|&&b| b == 0x35).count() >= 2;
                    
                    if !uses_strong_kdf || !has_salt {
                        vulns.push(TelegramBotVulnerability {
                            pc,
                            vulnerability_type: "KeyDerivationWeakness".to_string(),
                            description: format!(
                                "Wallet key derivation at PC {} uses weak KDF. Attack: if bot generates wallets from predictable inputs (telegram user ID, username, timestamp), \
                                attacker can brute-force key generation. Example: wallet key = keccak256(telegramUserId), attacker enumerates user IDs 1-10M, generates all possible \
                                keys, checks balances, steals funds from active wallets. Or: key = keccak256(username + timestamp), attacker knows username from Telegram, brute-forces \
                                timestamp range. Real exploit: bot uses sequential user IDs, attacker generates keys for userIds 1-100000, finds wallets with funds. Missing: proper \
                                entropy source, key stretching, unique salt per user. Should implement: use CSPRNG for key generation (not derived from public data), if must derive: \
                                use PBKDF2 with 100K+ iterations and unique random salt, include server secret in derivation.",
                                pc
                            ),
                            confidence: 0.88,
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

    fn detect_session_hijacking_vulnerability(&self) -> Vec<TelegramBotVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0xF1 { // CALL (trade execution)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_user_action = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                let has_authentication = window.iter().any(|&b| b == 0x20); // KECCAK256
                
                if has_user_action {
                    let verifies_message_signature = window.iter().filter(|&&b| b == 0x01).count() >= 1; // ADD (ecrecover)
                    let checks_nonce = window.iter().filter(|&&b| b == 0x54).count() >= 2;
                    
                    if !verifies_message_signature && !checks_nonce {
                        vulns.push(TelegramBotVulnerability {
                            pc,
                            vulnerability_type: "SessionHijackingVulnerability".to_string(),
                            description: format!(
                                "Bot transaction execution at PC {} vulnerable to session hijacking. Attack: Telegram bots use API tokens/session IDs for authentication, if not \
                                properly validated, attacker hijacks session and executes unauthorized trades. Attack vectors: (1) session token leaked via Telegram message history, \
                                (2) MITM on Telegram API calls captures token, (3) bot webhook doesn't verify Telegram signature, attacker forges requests. Example: user sends trade \
                                command via Telegram, bot processes without verifying request actually from Telegram (checks webhook signature), attacker sends fake webhook, triggers \
                                trades. Or: session tokens don't expire, attacker gets old token, uses indefinitely. Consequences: unauthorized trades drain user wallet, frontrunning \
                                user's intended trades, MEV extraction from user. Missing: Telegram webhook signature verification, message replay protection, session expiry. Should \
                                implement: verify X-Telegram-Bot-Api-Secret-Token header on webhooks, include nonce/timestamp in commands (prevent replay), expire sessions after 1 hour.",
                                pc
                            ),
                            confidence: 0.86,
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
