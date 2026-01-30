use crate::bytecode::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainIdHardforkVulnerability {
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

/// CHAINID Opcode Hard Fork Detector
///
/// Detects contracts that may break or have vulnerabilities due to CHAINID opcode
/// introduced in Istanbul hard fork (EIP-1344). Pre-Istanbul chains return 0 for CHAINID.
///
/// Vulnerability Scenarios:
/// - Contracts deployed before Istanbul assuming CHAINID is always available
/// - Signature verification relying on CHAINID on pre-Istanbul chains
/// - Cross-chain replay protection broken on older EVM versions
/// - Hard fork timing attacks using CHAINID availability
/// - Layer 2 chains with different CHAINID implementation timings
///
/// Real-World Impact:
/// - Signature replay attacks on chains without CHAINID
/// - Cross-chain bridges broken due to CHAINID assumptions
/// - DeFi protocols with replay vulnerabilities
/// - Multi-chain contracts with inconsistent behavior
///
/// Detection Strategy:
/// - Identifies CHAINID usage without fallback
/// - Detects signature verification depending solely on CHAINID
/// - Looks for CHAINID in critical security logic
/// - Checks for CHAINID without version detection
/// - Identifies missing hard fork compatibility checks
pub struct ChainidOpcodeHardforkDetector {
    bytecode: Vec<u8>,
}

impl ChainidOpcodeHardforkDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self, bytecode: &[u8]) -> Vec<ChainIdHardforkVulnerability> {
        self.detect(&self.bytecode)
            .into_iter()
            .map(|finding| ChainIdHardforkVulnerability {
                location: finding.pc,
                severity: format!("{:?}", finding.severity),
                description: finding.description,
                confidence: finding.confidence as f32,
            })
            .collect()
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: CHAINID without fallback (hard fork incompatibility)
            if bytecode[i] == 0x46 {
                if self.has_chainid_without_fallback(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "CHAINID hard fork risk: Using CHAINID without fallback breaks on pre-Istanbul chains where opcode returns 0".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            // Pattern 2: CHAINID in signature verification (critical security)
            if bytecode[i] == 0x46 {
                if self.has_chainid_in_signature_verification(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "CHAINID signature dependency: Signature verification depends on CHAINID, fails on pre-Istanbul chains enabling replay".to_string(),
                        pc: i,
                        confidence: 0.89,
                    });
                }
            }

            // Pattern 3: CHAINID with zero check (detects hard fork but may be mishandled)
            if bytecode[i] == 0x46 {
                if self.has_chainid_zero_check_mishandling(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "CHAINID zero handling: Contract checks for CHAINID==0 but may not handle pre-Istanbul behavior correctly".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            // Pattern 4: CHAINID in initialization (deployment timing issue)
            if bytecode[i] == 0x46 {
                if self.has_chainid_in_constructor(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "CHAINID in constructor: Constructor stores CHAINID, breaks if deployed before Istanbul or on incompatible chain".to_string(),
                        pc: i,
                        confidence: 0.83,
                    });
                }
            }

            // Pattern 5: Multiple CHAINID operations (complex chain-dependent logic)
            if bytecode[i] == 0x46 {
                if self.has_complex_chainid_logic(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Complex CHAINID logic: Multiple CHAINID operations increase risk of hard fork compatibility issues".to_string(),
                        pc: i,
                        confidence: 0.82,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    fn has_chainid_without_fallback(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 20.min(bytecode.len().saturating_sub(pos));
        let mut has_zero_check = false;
        let mut has_fallback_logic = false;

        // Check for CHAINID followed by zero validation
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x15 => has_zero_check = true, // ISZERO (checking if CHAINID is 0)
                    0x57 => {
                        // JUMPI (branching on zero check)
                        if has_zero_check {
                            has_fallback_logic = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // CHAINID without proper zero check/fallback
        !has_zero_check || !has_fallback_logic
    }

    fn has_chainid_in_signature_verification(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 50.min(bytecode.len().saturating_sub(pos));
        let lookback = 30.min(pos);
        
        let mut has_keccak = false;
        let mut has_ecrecover = false;
        let mut has_signature_data = false;

        // Check for signature hash construction with CHAINID
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x20 => has_keccak = true, // KECCAK256 (signature hash)
                    0x01 => has_ecrecover = true, // ECRECOVER precompile
                    _ => {}
                }
            }
        }

        // Check for signature components before CHAINID
        for offset in 1..=lookback {
            if pos >= offset {
                if bytecode[pos - offset] == 0x51 || bytecode[pos - offset] == 0x35 {
                    has_signature_data = true;
                    break;
                }
            }
        }

        // CHAINID in signature verification flow
        has_keccak && (has_ecrecover || has_signature_data)
    }

    fn has_chainid_zero_check_mishandling(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 25.min(bytecode.len().saturating_sub(pos));
        let mut has_iszero = false;
        let mut has_eq_zero = false;
        let mut has_revert = false;
        let mut has_alternative_logic = false;

        // Check handling of CHAINID == 0
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x15 => has_iszero = true, // ISZERO
                    0x14 => {
                        // EQ - checking if CHAINID == 0
                        if pos + offset > 0 && bytecode[pos + offset - 1] == 0x60 {
                            has_eq_zero = true;
                        }
                    }
                    0xfd => has_revert = true, // REVERT (rejecting zero)
                    0x54 | 0x55 => {
                        // SLOAD/SSTORE (alternative storage-based logic)
                        if has_iszero || has_eq_zero {
                            has_alternative_logic = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Checks for zero but only reverts (no alternative logic)
        (has_iszero || has_eq_zero) && has_revert && !has_alternative_logic
    }

    fn has_chainid_in_constructor(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 30.min(bytecode.len().saturating_sub(pos));
        let lookback = 40.min(pos);
        
        let mut has_sstore = false;
        let mut is_constructor = false;
        let mut has_codecopy = false;

        // Check if this is in constructor context
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x39 => has_codecopy = true, // CODECOPY (constructor pattern)
                    0x36 => {
                        // CALLDATASIZE - constructor check
                        if has_codecopy {
                            is_constructor = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Check for SSTORE after CHAINID
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if bytecode[pos + offset] == 0x55 {
                    has_sstore = true;
                    break;
                }
            }
        }

        // CHAINID stored during construction
        has_sstore && is_constructor
    }

    fn has_complex_chainid_logic(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 100.min(bytecode.len().saturating_sub(pos));
        let mut chainid_count = 1; // Current CHAINID
        let mut operations_count = 0;

        // Count additional CHAINID operations nearby
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if bytecode[pos + offset] == 0x46 {
                    chainid_count += 1;
                }
                if matches!(bytecode[pos + offset], 0x01..=0x1d | 0x50..=0x5b) {
                    operations_count += 1;
                }
            }
        }

        // Multiple CHAINID operations with complex logic
        chainid_count >= 3 || (chainid_count >= 2 && operations_count >= 15)
    }
}
