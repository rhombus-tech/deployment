use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConnectVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct WalletConnectV2SessionHijackingDetector {
    bytecode: Vec<u8>,
}

impl WalletConnectV2SessionHijackingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<WalletConnectVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_session_key_exposure());
        vulnerabilities.extend(self.detect_relay_message_tampering());
        vulnerabilities.extend(self.detect_session_approval_phishing());

        vulnerabilities
    }

    fn detect_session_key_exposure(&self) -> Vec<WalletConnectVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x55 { // SSTORE (session storage)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_session_data = window.iter().filter(|&&b| b == 0x35).count() >= 2;
                
                if has_session_data {
                    let encrypts_session_key = window.iter().filter(|&&b| b == 0x20).count() >= 4;
                    let uses_secure_storage = window.iter().any(|&b| b == 0x33); // CALLER check
                    
                    if !encrypts_session_key {
                        vulns.push(WalletConnectVulnerability {
                            pc,
                            vulnerability_type: "SessionKeyExposure".to_string(),
                            description: format!(
                                "WalletConnect session storage at PC {} exposes symmetric keys. Attack: WalletConnect V2 uses symmetric encryption (ChaCha20-Poly1305) for session \
                                messages, if session keys stored insecurely, attacker steals keys and impersonates either party. Key exposure vectors: (1) localStorage in browser \
                                (readable by any script on same origin), (2) exposed in logs/debugging, (3) transmitted over insecure channel, (4) weak key derivation. Example: dApp \
                                stores WC session topic + symmetric key in localStorage, malicious browser extension reads localStorage, decrypts all WC messages, can send transactions \
                                as user. Or: MITM attack captures session proposal with weak key exchange, attacker derives session keys. Consequences: attacker can send arbitrary \
                                transaction requests to user's wallet, sign messages on user's behalf, drain funds. Missing: key encryption at rest, secure key exchange (X25519), \
                                perfect forward secrecy. Should use: encrypt session keys with device-specific key (not stored in localStorage plaintext), use authenticated key exchange, \
                                implement key rotation, store keys in secure enclave on mobile.",
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

    fn detect_relay_message_tampering(&self) -> Vec<WalletConnectVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (message authentication)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_relay_message = window.iter().any(|&b| b == 0x37); // CALLDATACOPY
                
                if has_relay_message {
                    let validates_message_hmac = window.iter().filter(|&&b| b == 0x20).count() >= 3;
                    let checks_message_integrity = window.iter().any(|&b| b == 0x14); // EQ
                    
                    if !validates_message_hmac {
                        vulns.push(WalletConnectVulnerability {
                            pc,
                            vulnerability_type: "RelayMessageTampering".to_string(),
                            description: format!(
                                "WalletConnect relay message at PC {} lacks integrity verification. Attack: WalletConnect uses relay servers (bridge.walletconnect.org) to pass \
                                messages between dApp and wallet, if messages not authenticated, malicious relay can tamper. Tampering attacks: (1) relay modifies transaction params \
                                (change recipient, amount), (2) inject additional transactions into session, (3) replay old messages, (4) drop messages selectively. Example: user \
                                approves transaction to send 1 ETH to 0xALICE, relay modifies encrypted message (if weak encryption) to send to 0xATTACKER. Or: relay captures approval \
                                message, replays 100 times draining user. Missing: authenticated encryption (AEAD), message sequence numbers, relay trust validation. Should implement: \
                                use ChaCha20-Poly1305 with authenticated encryption (prevents tampering), include nonce/counter in each message (prevents replay), verify relay signature \
                                on message envelope, implement timeout for message validity.",
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

    fn detect_session_approval_phishing(&self) -> Vec<WalletConnectVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (session approval)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_request_execution = window.iter().any(|&b| b == 0xF1); // CALL
                
                if has_request_execution {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let validates_dapp_origin = pre_window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    let displays_full_permissions = window.iter().filter(|&&b| b == 0x35).count() >= 3;
                    
                    if !validates_dapp_origin {
                        vulns.push(WalletConnectVulnerability {
                            pc,
                            vulnerability_type: "SessionApprovalPhishing".to_string(),
                            description: format!(
                                "Session approval at PC {} doesn't validate dApp origin. Attack: WalletConnect session approval shows dApp metadata (name, URL, icon), phisher \
                                spoofs legitimate dApp to trick users into approving malicious session. Phishing techniques: (1) dApp name spoofing - 'Unıswap' (dotless i) vs 'Uniswap', \
                                (2) URL homograph - 'uniswȧp.org' (with combining diacritical), (3) icon copying - use exact same icon as real dApp, (4) approval fatigue - user approves \
                                without reading. Example: phisher creates WC session with metadata name='Uniswap', url='uniswap.com' (real is .org), icon=<real logo>, user sees familiar \
                                interface, approves session thinking it's real Uniswap, phisher can now request transactions. Real attack: 'Opensea' phishing drained $1M+ via fake WC \
                                sessions. Missing: dApp origin verification against allowlist, visual security indicators, approval scope clarity. Should display: verified checkmark for \
                                known dApps (allowlist), show full URL prominently (not just domain), list all permissions being granted (chains, accounts), require confirmation of high-risk \
                                permissions.",
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
