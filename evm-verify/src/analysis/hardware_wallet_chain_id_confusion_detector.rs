use crate::bytecode::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareWalletChainIdVulnerability {
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

/// Hardware Wallet Chain ID Confusion Detector
///
/// Detects vulnerabilities where malicious dApps exploit hardware wallet users by
/// presenting transactions on unexpected chains, leading to replay attacks or fund loss.
///
/// Attack Vectors:
/// - Cross-chain replay attacks using same addresses on different chains
/// - Phishing sites showing mainnet UI but signing on testnets
/// - Layer 2 chains with identical addresses but different security
/// - Chain ID manipulation in EIP-155 signatures
/// - Hardware wallets not clearly displaying chain context
///
/// Real-World Cases:
/// - $20M+ lost in cross-chain replay attacks
/// - Users signing mainnet-value transactions on testnets
/// - Bridge exploits leveraging chain confusion
/// - Multichain wallet confusion leading to wrong chain deployments
///
/// Detection Strategy:
/// - Identifies contracts that don't validate CHAINID
/// - Detects signature verification without chain binding
/// - Looks for cross-chain bridge operations without proper validation
/// - Checks for replay protection mechanisms
/// - Identifies contracts operating across multiple chains
pub struct HardwareWalletChainIdConfusionDetector;

impl HardwareWalletChainIdConfusionDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: Signature verification without CHAINID check
            // ECRECOVER without corresponding CHAINID validation
            if bytecode[i] == 0x01 {
                if self.has_signature_without_chainid(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Chain ID confusion: Signature verification without CHAINID check enables cross-chain replay attacks on hardware wallets".to_string(),
                        pc: i,
                        confidence: 0.89,
                    });
                }
            }

            // Pattern 2: Missing CHAINID opcode in signature construction
            // Signature hash construction without CHAINID (EIP-155 violation)
            if bytecode[i] == 0x20 {
                if self.has_signature_hash_without_chainid(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "EIP-155 violation: Signature hash construction missing CHAINID, vulnerable to replay on different chains".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            // Pattern 3: Cross-chain bridge without chain validation
            // Bridge operations that don't verify destination chain
            if bytecode[i] == 0xf1 || bytecode[i] == 0xfa {
                if self.has_bridge_without_chain_check(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Cross-chain bridge: Missing chain validation allows wrong-chain deposits from hardware wallets".to_string(),
                        pc: i,
                        confidence: 0.85,
                    });
                }
            }

            // Pattern 4: CHAINID check but with hardcoded value
            // Hardcoded chain IDs are vulnerable when contract is deployed to multiple chains
            if bytecode[i] == 0x46 {
                if self.has_hardcoded_chainid_comparison(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Hardcoded CHAINID: Contract assumes specific chain, hardware wallet users vulnerable when deployed to multiple chains".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            // Pattern 5: Domain separator without CHAINID
            // EIP-712 domain separator missing CHAINID component
            if bytecode[i] == 0x20 {
                if self.has_domain_separator_without_chainid(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "EIP-712 domain separator: Missing CHAINID in domain separator enables cross-chain signature replay".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    pub fn detect_vulnerabilities(&self) -> Vec<HardwareWalletChainIdVulnerability> {
        self.detect(&[])
            .into_iter()
            .map(|finding| HardwareWalletChainIdVulnerability {
                location: finding.pc,
                severity: format!("{:?}", finding.severity),
                description: finding.description,
                confidence: finding.confidence as f32,
            })
            .collect()
    }

    fn has_signature_without_chainid(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 50.min(pos);
        let window = 30.min(bytecode.len().saturating_sub(pos));
        
        let mut has_chainid = false;
        let mut has_signature_data = false;
        let mut has_ecrecover_call = false;

        // Check for CHAINID opcode before ECRECOVER
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x46 => has_chainid = true, // CHAINID
                    0x20 => has_signature_data = true, // KECCAK256 (signature hash)
                    _ => {}
                }
            }
        }

        // Check if this is actually ECRECOVER call
        for offset in 0..window {
            if pos + offset < bytecode.len() {
                if bytecode[pos + offset] == 0xf1 || bytecode[pos + offset] == 0xfa {
                    has_ecrecover_call = true;
                    break;
                }
            }
        }

        // ECRECOVER without CHAINID in the signature construction
        has_signature_data && has_ecrecover_call && !has_chainid
    }

    fn has_signature_hash_without_chainid(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let mut has_chainid = false;
        let mut has_signature_components = 0;
        let mut has_message_hash = false;

        // Check for typical EIP-155 signature components
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x46 => has_chainid = true, // CHAINID
                    0x51 => has_signature_components += 1, // MLOAD (v, r, s)
                    0x35 => has_message_hash = true, // CALLDATALOAD
                    _ => {}
                }
            }
        }

        // Signature hash with components but no CHAINID
        has_signature_components >= 2 && has_message_hash && !has_chainid
    }

    fn has_bridge_without_chain_check(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut has_chainid = false;
        let mut has_bridge_selector = false;
        let mut has_destination_param = false;

        // Check for bridge function patterns
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x46 => has_chainid = true, // CHAINID
                    0x63 => {
                        // Check for common bridge selectors
                        if pos >= offset + 4 {
                            let selector_area = &bytecode[pos - offset + 1..pos - offset + 5];
                            // Common patterns: deposit, bridge, lock, etc.
                            if selector_area[0] == 0x47 || selector_area[0] == 0xb6 {
                                has_bridge_selector = true;
                            }
                        }
                    }
                    0x35 => has_destination_param = true, // CALLDATALOAD (chain param)
                    _ => {}
                }
            }
        }

        // Bridge call without CHAINID validation
        has_bridge_selector && has_destination_param && !has_chainid
    }

    fn has_hardcoded_chainid_comparison(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 10.min(bytecode.len().saturating_sub(pos));
        let mut has_push_constant = false;
        let mut has_eq_comparison = false;

        // CHAINID followed immediately by PUSH (constant) and EQ
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x60..=0x62 => has_push_constant = true, // PUSH1-PUSH3 (chain ID)
                    0x14 => has_eq_comparison = true, // EQ
                    _ => {}
                }
            }
        }

        has_push_constant && has_eq_comparison
    }

    fn has_domain_separator_without_chainid(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 60.min(pos);
        let mut has_chainid = false;
        let mut has_eip712_typehash = false;
        let mut has_name_hash = false;
        let mut has_version_hash = false;

        // EIP-712 domain separator construction pattern
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x46 => has_chainid = true, // CHAINID
                    0x7f => {
                        // PUSH32 - check for EIP-712 typehash or string hashes
                        if pos >= offset + 32 {
                            let pushed_data = &bytecode[pos - offset + 1..pos - offset + 33];
                            // EIP712Domain typehash or string hashes
                            if pushed_data[0] == 0x8b || pushed_data[0] == 0xfc {
                                has_eip712_typehash = true;
                            }
                            // Name or version hashes
                            if pushed_data[31] != 0x00 {
                                if has_eip712_typehash {
                                    has_name_hash = true;
                                } else if has_name_hash {
                                    has_version_hash = true;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // EIP-712 domain separator without CHAINID
        has_eip712_typehash && (has_name_hash || has_version_hash) && !has_chainid
    }
}
