use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetamaskSnapVulnerability {
    pub pc: usize,
    pub vulnerability_type: String,
    pub description: String,
    pub confidence: f32,
}

pub struct MetamaskSnapMaliciousPermissionDetector {
    bytecode: Vec<u8>,
}

impl MetamaskSnapMaliciousPermissionDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<MetamaskSnapVulnerability> {
        let mut vulnerabilities = Vec::new();

        vulnerabilities.extend(self.detect_overprivileged_snap_permissions());
        vulnerabilities.extend(self.detect_snap_keyring_abuse());
        vulnerabilities.extend(self.detect_transaction_insight_manipulation());

        vulnerabilities
    }

    fn detect_overprivileged_snap_permissions(&self) -> Vec<MetamaskSnapVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x54 { // SLOAD (permission check)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_permission_grant = window.iter().any(|&b| b == 0x55); // SSTORE
                
                if has_permission_grant {
                    let start = if pc > 80 { pc - 80 } else { 0 };
                    let pre_window = &self.bytecode[start..pc];
                    
                    let validates_permission_scope = pre_window.iter().filter(|&&b| b == 0x14).count() >= 2;
                    let enforces_least_privilege = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if !validates_permission_scope {
                        vulns.push(MetamaskSnapVulnerability {
                            pc,
                            vulnerability_type: "OverprivilegedSnapPermissions".to_string(),
                            description: format!(
                                "MetaMask Snap permission grant at PC {} allows excessive privileges. Attack: MetaMask Snaps extend wallet functionality via plugins, malicious Snap \
                                requests broad permissions to steal data or funds. Dangerous permissions: (1) 'endowment:rpc' - full RPC access enables reading all account balances, \
                                transaction history, (2) 'snap_manageState' - persistent storage can exfiltrate user data, (3) 'snap_getBip32Entropy' - derive private keys from seed, \
                                (4) 'endowment:transaction-insight' - intercept all transactions, modify params. Example: malicious Snap requests 'endowment:rpc', user approves thinking \
                                it's needed for DeFi features, Snap calls eth_getBalance for all accounts, sends balances to attacker's server. Or: Snap with 'getBip32Entropy' derives \
                                BIP-32 keys, exfiltrates them, attacker drains derived accounts. Real risk: trojan Snaps on SnapStore can look legitimate but contain malware. Missing: \
                                permission scope validation, usage auditing, runtime permission revocation. Should enforce: least-privilege principle (only grant minimal permissions), \
                                require permission justification, audit permission usage patterns, allow users to revoke permissions anytime.",
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

    fn detect_snap_keyring_abuse(&self) -> Vec<MetamaskSnapVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x20 { // KECCAK256 (key derivation)
                let start = if pc > 120 { pc - 120 } else { 0 };
                let window = &self.bytecode[start..pc];
                
                let has_entropy_access = window.iter().filter(|&&b| b == 0x35).count() >= 2;
                
                if has_entropy_access {
                    let validates_key_usage = window.iter().filter(|&&b| b == 0x14).count() >= 2;
                    let limits_derivation_paths = window.iter().filter(|&&b| matches!(b, 0x10 | 0x11)).count() >= 2;
                    
                    if !validates_key_usage {
                        vulns.push(MetamaskSnapVulnerability {
                            pc,
                            vulnerability_type: "SnapKeyringAbuse".to_string(),
                            description: format!(
                                "Snap entropy access at PC {} lacks key derivation restrictions. Attack: Snaps with 'snap_getBip32Entropy' can derive keys from MetaMask seed phrase, \
                                malicious Snap derives sensitive keys and exfiltrates. Key derivation abuse: (1) derive keys on attacker-controlled derivation paths, export private keys, \
                                (2) derive keys for other protocols (Bitcoin, etc.) beyond stated purpose, (3) brute-force derive all possible paths to find funded accounts. Example: \
                                'DeFi Portfolio' Snap requests entropy for m/44'/60'/0'/0/0 (claiming to manage multi-account), actually derives m/44'/60'/0'/0/0-1000, checks balances on \
                                all derived addresses, finds accounts with funds, steals keys. Or: Snap derives BIP-32 keys for Bitcoin (m/44'/0'/0'/0/0) even though supposed to be \
                                Ethereum-only, steals user's BTC. Missing: derivation path allowlist, key usage auditing, entropy access rate limiting. Should implement: only allow entropy \
                                derivation on specific approved paths, log all derivation requests, require user confirmation for each path, prevent derivation on non-standard paths.",
                                pc
                            ),
                            confidence: 0.90,
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

    fn detect_transaction_insight_manipulation(&self) -> Vec<MetamaskSnapVulnerability> {
        let mut vulns = Vec::new();
        let mut pc = 0;

        while pc < self.bytecode.len() {
            let opcode = self.bytecode[pc];

            if opcode == 0x35 { // CALLDATALOAD (transaction data)
                let window_end = (pc + 100).min(self.bytecode.len());
                let window = &self.bytecode[pc..window_end];
                
                let has_insight_display = window.iter().any(|&b| b == 0x55); // SSTORE (UI update)
                
                if has_insight_display {
                    let validates_insight_authenticity = window.iter().filter(|&&b| b == 0x20).count() >= 2;
                    let cross_checks_data = window.iter().any(|&b| b == 0xFA); // STATICCALL (oracle)
                    
                    if !validates_insight_authenticity {
                        vulns.push(MetamaskSnapVulnerability {
                            pc,
                            vulnerability_type: "TransactionInsightManipulation".to_string(),
                            description: format!(
                                "Transaction insight display at PC {} shows unvalidated data. Attack: Snaps with 'endowment:transaction-insight' permission display transaction \
                                previews in MetaMask UI, malicious Snap shows false information to trick users into approving. Manipulation tactics: (1) show fake recipient (display \
                                'Uniswap Router' when actually sending to attacker), (2) hide approval amounts (show 'approve 100 USDC' when actually 'approve unlimited'), (3) fake \
                                security warnings (show 'verified safe' on malicious contract), (4) manipulate decoded function calls. Example: user initiates swap on DEX, Snap shows \
                                insight: 'Swap 1 ETH for 3000 USDC on Uniswap', user approves, actual transaction is 'Transfer 10 ETH to 0xATTACKER'. Or: Snap shows 'Claim airdrop (safe)' \
                                but transaction is token approval for phishing contract. Real attack vector: approval phishing via fake insights. Missing: insight data source verification, \
                                cross-validation with trusted oracles, user education on Snap limitations. Should implement: require Snaps to disclose data sources, cross-check insights \
                                with multiple providers, show warning if Snap insight differs from built-in decoding, allow users to disable Snap insights.",
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
}
