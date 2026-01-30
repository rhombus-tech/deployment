use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinbaseWalletDeeplinkVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct CoinbaseWalletMobileDeeplinkHijackingDetector {
    bytecode: Vec<u8>,
}

impl CoinbaseWalletMobileDeeplinkHijackingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<CoinbaseWalletDeeplinkVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_deeplink_parameter_injection());
        vulnerabilities.extend(self.detect_return_url_manipulation());
        vulnerabilities.extend(self.detect_app_switching_phishing());

        vulnerabilities
    }

    fn detect_deeplink_parameter_injection(&self) -> Vec<CoinbaseWalletDeeplinkVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x35 { // CALLDATALOAD (deeplink params)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_url_construction = window.iter().any(|&b| b == 0x20); // KECCAK256
                
                if has_url_construction {
                    let sanitizes_parameters = window.iter().filter(|&&b| b == 0x14).count() >= 2;
                    let validates_url_format = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    
                    if !sanitizes_parameters {
                        vulns.push(CoinbaseWalletDeeplinkVulnerability {
                            pc,
                            vulnerability_type: "DeeplinkParameterInjection".to_string(),
                            description: format!(
                                "Deeplink URL construction at PC {} vulnerable to parameter injection. Attack: mobile dApp opens Coinbase Wallet via deeplink (cbwallet://), if \
                                parameters not sanitized, malicious dApp injects malicious values. Deeplink injection: (1) normal deeplink: cbwallet://dapp?url=https://uniswap.org, (2) \
                                injected: cbwallet://dapp?url=https://uniswap.org&redirect=https://phishing.com, (3) wallet processes redirect parameter, sends user to phishing site after \
                                signing. Or: inject transaction parameters - cbwallet://send?to=0xLEGIT&amount=1&to=0xATTACKER&amount=1000, if wallet parses naively, uses last 'to' \
                                parameter. Example: dApp constructs deeplink with user input: address=${{userInput}}, attacker inputs '0xLEGIT&to=0xATTACKER', creates cbwallet://send?to=0xLEGIT&to=0xATTACKER, \
                                wallet sends to attacker. Missing: URL parameter encoding, injection sanitization, parameter allowlist. Should implement: URL-encode all parameters, validate \
                                parameter format before constructing deeplink, use POST body instead of URL params for sensitive data, implement deeplink signature/HMAC.",
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

    fn detect_return_url_manipulation(&self) -> Vec<CoinbaseWalletDeeplinkVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (URL validation)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_return_url = window.iter().any(|&b| b == 0x35); // CALLDATALOAD
                
                if has_return_url {
                    let validates_return_origin = window.iter().filter(|&&b| b == 0x14).count() >= 2;
                    let checks_url_whitelist = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    
                    if !validates_return_origin {
                        vulns.push(CoinbaseWalletDeeplinkVulnerability {
                            pc,
                            vulnerability_type: "ReturnUrlManipulation".to_string(),
                            description: format!(
                                "Return URL handling at PC {} doesn't validate redirect destination. Attack: dApp specifies return URL in deeplink, malicious dApp provides phishing URL, \
                                wallet redirects user after transaction. Return URL attack: (1) legitimate flow: cbwallet://send?returnUrl=myapp://success, (2) malicious: cbwallet://send?returnUrl=phishing://steal-keys, \
                                (3) user approves transaction in Coinbase Wallet, (4) wallet redirects to phishing://steal-keys, (5) phishing app opens, looks like Coinbase Wallet, asks for \
                                seed phrase 'for verification'. Example: user approves swap, wallet redirects to malicious app claiming 'Transaction failed, please enter recovery phrase', \
                                user enters seed, attacker steals. Or: open redirect vulnerability - returnUrl=https://coinbase.com@attacker.com, wallet doesn't validate domain properly. \
                                Missing: return URL whitelist, domain validation, user confirmation. Should enforce: only allow returns to app's registered custom URL scheme (myapp://), \
                                validate returnUrl matches app bundle ID, show 'Returning to [App Name]' confirmation, block http/https return URLs (only custom schemes).",
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

    fn detect_app_switching_phishing(&self) -> Vec<CoinbaseWalletDeeplinkVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (session state)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let handles_app_return = window.iter().any(|&b| b == 0x55); // SSTORE
                
                if handles_app_return {
                    let validates_return_authenticity = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    let checks_session_token = window.iter().filter(|&&b| b == 0x14).count() >= 2;
                    
                    if !validates_return_authenticity {
                        vulns.push(CoinbaseWalletDeeplinkVulnerability {
                            pc,
                            vulnerability_type: "AppSwitchingPhishing".to_string(),
                            description: format!(
                                "App switching state validation at PC {} vulnerable to phishing during wallet return. Attack: user switches to Coinbase Wallet to sign, malicious app \
                                intercepts return and impersonates dApp. App switching attack: (1) user in dApp, clicks 'Sign Transaction', (2) dApp opens cbwallet:// deeplink, (3) user \
                                approves in Coinbase Wallet, (4) wallet returns control, (5) malicious app listening for cbwallet return events, (6) malicious app activates instead of real \
                                dApp, (7) shows fake 'Transaction Failed' UI, (8) tricks user into doing something harmful. Example: user swaps on mobile Uniswap, approves in Coinbase Wallet, \
                                malicious app 'CryptoTracker' intercepts return, shows 'Transaction failed, reconnect wallet' prompt, user connects, gives approvals to attacker's contracts. \
                                Or: timing attack - malicious app waits for legitimate dApp to open wallet, quickly opens itself after user approves, user thinks they're back in real dApp. \
                                Missing: deeplink session tokens, app verification on return, visual continuity. Should implement: generate unique session token before opening wallet, include \
                                in deeplink, verify token when wallet returns, show app bundle ID on wallet return confirmation, implement timeout for wallet returns (reject after 5 min).",
                                pc
                            ),
                            confidence: 0.82,
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
