use crate::bytecode::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrezorPassphraseVulnerability {
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

/// Trezor Passphrase Injection Detector
///
/// Detects vulnerabilities where malicious contracts or dApps can manipulate users into
/// entering incorrect passphrases on Trezor hardware wallets, leading to access of wrong accounts
/// or creation of honeypot wallets.
///
/// Attack Vectors:
/// - Phishing sites that prompt for "verification" passphrases
/// - Contracts that request specific passphrase formats
/// - UI manipulation showing fake passphrase entry screens
/// - Session hijacking during passphrase entry
/// - Malicious dApps requesting passphrase re-entry
///
/// Real-World Impact:
/// - Users create wallets with attacker-known passphrases
/// - Funds sent to honeypot accounts controlled by attackers
/// - BIP39 passphrase confusion leading to permanent fund loss
///
/// Detection Strategy:
/// - Identifies contracts requesting user input that could be passphrases
/// - Detects string manipulation that could extract passphrase data
/// - Looks for phishing patterns in user interaction flows
/// - Checks for suspicious account derivation patterns
/// - Identifies contracts that validate or check user secrets
pub struct TrezorPassphraseInjectionDetector;

impl TrezorPassphraseInjectionDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: User secret validation
            // KECCAK256 on user input suggests passphrase or secret handling
            if bytecode[i] == 0x20 {
                if self.has_user_secret_validation(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Trezor passphrase injection risk: Contract validates user secrets, could be used for passphrase phishing".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            // Pattern 2: String input with length checks (passphrase pattern)
            // CALLDATALOAD followed by length validation
            if bytecode[i] == 0x35 {
                if self.has_passphrase_input_pattern(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Passphrase-like input detected: Contract accepts string input with validation, potential Trezor phishing vector".to_string(),
                        pc: i,
                        confidence: 0.85,
                    });
                }
            }

            // Pattern 3: Signature verification with secret input
            // ECRECOVER with user-provided data (could validate attacker passphrase)
            if bytecode[i] == 0x01 {
                if self.has_secret_signature_verification(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Secret signature verification: Contract may be used to validate attacker-provided passphrases".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            // Pattern 4: Account derivation with user input
            // Complex calculation suggesting BIP32/BIP44 derivation with user data
            if bytecode[i] == 0x02 {
                if self.has_account_derivation_with_input(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Account derivation pattern: Contract performs calculations that could be exploited for passphrase injection".to_string(),
                        pc: i,
                        confidence: 0.82,
                    });
                }
            }

            // Pattern 5: Multiple KECCAK operations on sequential data (BIP39 mnemonic)
            if bytecode[i] == 0x20 {
                if self.has_mnemonic_processing_pattern(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Mnemonic processing detected: Contract may be collecting or validating BIP39 phrases, critical phishing risk".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    pub fn detect_vulnerabilities(&self, bytecode: Vec<u8>) -> Vec<TrezorPassphraseVulnerability> {
        self.detect(&bytecode)
            .into_iter()
            .map(|finding| TrezorPassphraseVulnerability {
                location: finding.pc,
                severity: format!("{:?}", finding.severity),
                description: finding.description,
                confidence: finding.confidence as f32,
            })
            .collect()
    }

    fn has_user_secret_validation(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 20.min(pos);
        let window = 15.min(bytecode.len().saturating_sub(pos));
        
        let mut has_calldataload = false;
        let mut has_comparison = false;
        let mut has_revert_on_fail = false;

        // Check for user input before hash
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x35 => has_calldataload = true, // CALLDATALOAD
                    _ => {}
                }
            }
        }

        // Check for comparison and revert after hash
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x14 => has_comparison = true, // EQ
                    0xfd => has_revert_on_fail = true, // REVERT
                    _ => {}
                }
            }
        }

        // Pattern: hash user input, compare, revert if wrong (secret validation)
        has_calldataload && has_comparison && has_revert_on_fail
    }

    fn has_passphrase_input_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let mut has_length_check = false;
        let mut has_min_length = false;
        let mut has_max_length = false;
        let mut has_string_copy = false;

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x12 => has_length_check = true, // LT, SLT (length checks)
                    0x37 => has_string_copy = true, // CALLDATACOPY
                    0x60..=0x7f => {
                        // Check for typical passphrase length bounds (8-256)
                        if bytecode[pos + offset] == 0x60 && pos + offset + 1 < bytecode.len() {
                            let val = bytecode[pos + offset + 1];
                            if val >= 8 && val <= 32 {
                                has_min_length = true;
                            }
                            if val >= 32 && val <= 128 {
                                has_max_length = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // String input with length validation suggests passphrase handling
        has_length_check && has_string_copy && (has_min_length || has_max_length)
    }

    fn has_secret_signature_verification(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 35.min(bytecode.len().saturating_sub(pos));
        let lookback = 25.min(pos);
        
        let mut has_ecrecover = false;
        let mut has_user_input = false;
        let mut has_hash_input = false;

        // ECRECOVER is at precompile address 0x01
        // Check if this is a CALL to address 0x01
        for offset in 0..window {
            if pos + offset < bytecode.len() {
                if bytecode[pos + offset] == 0xf1 || bytecode[pos + offset] == 0xfa {
                    // Check for 0x01 address before call
                    if pos + offset >= 2 {
                        if bytecode[pos + offset - 1] == 0x60 && bytecode[pos + offset] == 0x01 {
                            has_ecrecover = true;
                        }
                    }
                }
            }
        }

        // Check for user input and hash
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x35 => has_user_input = true, // CALLDATALOAD
                    0x20 => has_hash_input = true, // KECCAK256
                    _ => {}
                }
            }
        }

        has_ecrecover && has_user_input && has_hash_input
    }

    fn has_account_derivation_with_input(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 25.min(bytecode.len().saturating_sub(pos));
        let lookback = 20.min(pos);
        
        let mut mul_count = 1; // Current MUL
        let mut add_count = 0;
        let mut has_large_constant = false;
        let mut has_user_input = false;

        // Check for user input
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x35 => has_user_input = true, // CALLDATALOAD
                    0x60..=0x7f => {
                        // Large constants used in BIP32 derivation
                        if bytecode[pos - offset] >= 0x63 { // PUSH4 or larger
                            has_large_constant = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Check for additional arithmetic (derivation calculations)
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x02 => mul_count += 1, // MUL
                    0x01 => add_count += 1, // ADD
                    _ => {}
                }
            }
        }

        // Complex arithmetic with user input and large constants
        has_user_input && has_large_constant && mul_count >= 2 && add_count >= 1
    }

    fn has_mnemonic_processing_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 60.min(bytecode.len().saturating_sub(pos));
        let mut keccak_count = 1; // Current KECCAK
        let mut sequential_data = false;
        let mut has_loop = false;
        let mut mload_count = 0;

        // Look for multiple hash operations on sequential data
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x20 => keccak_count += 1, // Another KECCAK256
                    0x57 => has_loop = true, // JUMPI (loop)
                    0x51 => mload_count += 1, // MLOAD (loading words)
                    0x01 => {
                        // ADD for incrementing pointer (sequential access)
                        if pos + offset >= 2 && bytecode[pos + offset - 1] == 0x60 {
                            let increment = bytecode.get(pos + offset - 1 + 1);
                            if increment == Some(&0x20) || increment == Some(&0x04) {
                                sequential_data = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Multiple hashes with sequential access pattern (BIP39 word processing)
        keccak_count >= 2 && sequential_data && mload_count >= 3 && has_loop
    }
}
