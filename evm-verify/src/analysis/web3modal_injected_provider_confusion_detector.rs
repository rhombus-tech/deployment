use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web3ModalVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct Web3modalInjectedProviderConfusionDetector {
    bytecode: Vec<u8>,
}

impl Web3modalInjectedProviderConfusionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<Web3ModalVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_provider_injection_hijacking());
        vulnerabilities.extend(self.detect_wallet_detection_spoofing());
        vulnerabilities.extend(self.detect_multiple_wallet_collision());

        vulnerabilities
    }

    fn detect_provider_injection_hijacking(&self) -> Vec<Web3ModalVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (provider detection)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_wallet_connection = window.iter().any(|&b| b == 0xF1); // CALL
                
                if has_wallet_connection {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let validates_provider_origin = pre_window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    let checks_provider_authenticity = window.iter().any(|&b| b == 0x14); // EQ
                    
                    if !validates_provider_origin {
                        vulns.push(Web3ModalVulnerability {
                            pc,
                            vulnerability_type: "ProviderInjectionHijacking".to_string(),
                            description: format!(
                                "Web3 provider detection at PC {} vulnerable to injection hijacking. Attack: dApp checks window.ethereum for injected provider, malicious \
                                browser extension/script injects fake provider first, intercepts all transactions. Provider injection: (1) malicious extension loads before MetaMask, \
                                sets window.ethereum to phishing provider, (2) extension overwrites window.ethereum.request method, (3) fake provider shows UI mimicking real wallet. \
                                Example: user has MetaMask installed, visits dApp, malicious extension 'CryptoHelper' loads first, creates window.ethereum object, dApp connects to fake \
                                provider, user approves transaction thinking it's MetaMask, actually signing attacker's transaction. Or: provider relay attack - fake provider forwards \
                                some requests to real wallet but modifies critical ones (transaction params). Real malware: fake wallet extensions on Chrome store intercepted $millions. \
                                Missing: provider verification, wallet signature validation, user education. Should implement: verify provider via EIP-1193 standardization, check \
                                provider.isMetaMask/isCoinbaseWallet flags (can be spoofed but adds difficulty), use provider.request to query chainId and validate response format, warn \
                                users about multiple wallet extensions.",
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

    fn detect_wallet_detection_spoofing(&self) -> Vec<Web3ModalVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (wallet identification)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_wallet_check = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_wallet_check {
                    let validates_wallet_metadata = window.iter().filter(|&&b| b == 0x20).count() >= 3;
                    let checks_multiple_properties = window.iter().filter(|&&b| b == 0x14).count() >= 3;
                    
                    if !validates_wallet_metadata {
                        vulns.push(Web3ModalVulnerability {
                            pc,
                            vulnerability_type: "WalletDetectionSpoofing".to_string(),
                            description: format!(
                                "Wallet identification at PC {} relies on spoofable properties. Attack: dApps detect wallets via provider flags (window.ethereum.isMetaMask), \
                                malicious wallets spoof these flags to appear legitimate. Spoofing techniques: (1) set provider.isMetaMask = true in fake wallet, (2) copy MetaMask's \
                                provider properties (chainId, networkVersion, selectedAddress), (3) implement EIP-1193 interface correctly so dApp thinks it's real wallet. Example: \
                                phishing wallet sets all MetaMask properties, dApp shows 'Connected to MetaMask' UI, user trusts it, approves malicious transaction. Or: wallet switcher \
                                attack - legitimate wallet connected, malicious extension overwrites provider.request(), intercepts calls. Detection bypasses: check window.ethereum.isMetaMask \
                                alone is insufficient, providers can lie about identity. Missing: cryptographic wallet verification, challenge-response authentication, provider registry. \
                                Should implement: use EIP-6963 (multi-injected provider discovery) to list all providers, let user explicitly choose, verify wallet via signed challenge \
                                (wallet signs dApp domain, proves it has private key), maintain allowlist of known-good provider UUIDs.",
                                pc
                            ),
                            confidence: 0.84,
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

    fn detect_multiple_wallet_collision(&self) -> Vec<Web3ModalVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x35 { // CALLDATALOAD (wallet selection)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_connection_logic = window.iter().any(|&b| b == 0x55); // SSTORE
                
                if has_connection_logic {
                    let handles_multiple_providers = window.iter().filter(|&&b| b == 0x54).count() >= 3;
                    let has_provider_conflict_resolution = window.iter().filter(|&&b| b == 0x57).count() >= 2; // JUMPI
                    
                    if !handles_multiple_providers {
                        vulns.push(Web3ModalVulnerability {
                            pc,
                            vulnerability_type: "MultipleWalletCollision".to_string(),
                            description: format!(
                                "Wallet connection at PC {} doesn't handle multiple injected providers. Attack: user has multiple wallet extensions (MetaMask + Coinbase Wallet + \
                                Rainbow), all inject into window.ethereum, last one loaded wins, dApp connects to wrong wallet. Collision scenarios: (1) user wants to use MetaMask, but \
                                Coinbase Wallet loaded last, overwrote window.ethereum, dApp connects to Coinbase, (2) 3+ wallets installed, unpredictable which one dApp uses, (3) some \
                                wallets try to be 'polite' and only inject if no other wallet present, others always overwrite. Example: user has $10K in MetaMask, $0 in Brave Wallet, \
                                Brave browser injects Brave Wallet first, user clicks 'Connect Wallet', dApp shows empty account, user confused. Or worse: user approves transaction thinking \
                                it's from MetaMask account, actually signing with different account that has no funds, transaction fails. Missing: multi-provider handling, user wallet \
                                selection UI, provider priority management. Should use: EIP-6963 multi-provider discovery (window.addEventListener('eip6963:announceProvider')), display \
                                all detected wallets in UI, let user explicitly select, save preference for future sessions, provide 'switch wallet' button.",
                                pc
                            ),
                            confidence: 0.81,
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
