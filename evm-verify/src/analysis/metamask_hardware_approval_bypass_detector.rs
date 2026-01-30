use crate::bytecode::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaMaskHardwareVulnerability {
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

/// MetaMask Hardware Approval Bypass Detector
///
/// Detects vulnerabilities where malicious contracts exploit MetaMask hardware wallet integration
/// to bypass approval screens or trick users into signing dangerous transactions.
///
/// Attack Vectors:
/// - Proxy contracts that change behavior after hardware approval
/// - Batch transactions where only first operation shown on device
/// - Off-chain signature requests that don't trigger hardware confirmation
/// - EIP-712 structured data that hides malicious fields
/// - Permit2 approvals that bypass standard approval UI
///
/// Real-World Cases:
/// - $3M+ drained via malicious permit signatures
/// - Hardware wallet users signing unlimited approvals unknowingly
/// - Batch operation attacks hiding malicious calls
/// - Cross-contract calls bypassing hardware verification
///
/// Detection Strategy:
/// - Identifies contracts with approval mechanisms that skip validation
/// - Detects EIP-712 signatures with hidden or complex data structures
/// - Looks for batch operations that could hide malicious actions
/// - Checks for proxy patterns that can change post-approval
/// - Identifies permit/approval functions with unusual parameters
pub struct MetamaskHardwareApprovalBypassDetector;

impl MetamaskHardwareApprovalBypassDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: EIP-712 signature with complex nested structures
            // Hardware wallets can't display nested struct details properly
            if bytecode[i] == 0x20 {
                if self.has_complex_eip712_structure(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "MetaMask hardware bypass: Complex EIP-712 nested structures cannot be verified on hardware wallet screen".to_string(),
                        pc: i,
                        confidence: 0.88,
                    });
                }
            }

            // Pattern 2: Permit2-style approvals (bypass standard approval UI)
            // Signature-based approvals don't trigger hardware warning screens
            if bytecode[i] == 0x63 && i + 4 < bytecode.len() {
                if self.has_permit2_bypass_pattern(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Permit2 approval bypass: Signature-based approval bypasses MetaMask hardware wallet approval screen".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            // Pattern 3: Batch multicall hiding malicious operations
            // Only first operation visible on hardware device
            if bytecode[i] == 0xf1 {
                if self.has_multicall_bypass_pattern(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Multicall bypass: Batch operations exceed hardware wallet display, hiding malicious calls from user".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            // Pattern 4: Upgradeable proxy with post-approval behavior change
            // Hardware approves current implementation, but can be changed
            if bytecode[i] == 0xf4 {
                if self.has_upgradeable_proxy_bypass(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Upgradeable proxy bypass: Contract can change behavior after hardware wallet approval".to_string(),
                        pc: i,
                        confidence: 0.85,
                    });
                }
            }

            // Pattern 5: Off-chain signature aggregation (hardware can't verify all)
            // Multiple signatures combined without individual hardware verification
            if bytecode[i] == 0x20 {
                if self.has_signature_aggregation_bypass(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Signature aggregation: Off-chain signature combination bypasses per-operation hardware verification".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    pub fn detect_vulnerabilities(&self, bytecode: Vec<u8>) -> Vec<MetaMaskHardwareVulnerability> {
        self.detect(&bytecode)
            .into_iter()
            .map(|finding| MetaMaskHardwareVulnerability {
                location: finding.pc,
                severity: format!("{:?}", finding.severity),
                description: finding.description,
                confidence: finding.confidence as f32,
            })
            .collect()
    }

    fn has_complex_eip712_structure(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 80.min(pos);
        let mut keccak_count = 1; // Current KECCAK
        let mut struct_hash_count = 0;
        let mut has_nested_encoding = false;
        let mut has_domain_separator = false;

        // EIP-712 nested struct pattern: multiple struct hashes
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x20 => keccak_count += 1, // Multiple KECCAK256 (struct hashing)
                    0x7f => {
                        // PUSH32 - could be typehash
                        if pos >= offset + 32 {
                            let data = &bytecode[pos - offset + 1..pos - offset + 33];
                            // EIP-712 typehashes often start with specific bytes
                            if data[0] >= 0x80 && data[0] <= 0xff {
                                struct_hash_count += 1;
                            }
                            // Domain separator
                            if data[0] == 0x8b {
                                has_domain_separator = true;
                            }
                        }
                    }
                    0x52 => {
                        // MSTORE in encoding suggests nested struct
                        if struct_hash_count >= 2 {
                            has_nested_encoding = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Multiple nested structs (>2 levels) can't be displayed on hardware
        keccak_count >= 3 && struct_hash_count >= 2 && has_nested_encoding && has_domain_separator
    }

    fn has_permit2_bypass_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        // Check for Permit2 function selectors
        if pos + 4 < bytecode.len() {
            let selector = &bytecode[pos + 1..pos + 5];
            
            // permit(address,PermitTransferFrom,bytes): Common Permit2 selector
            // permitTransferFrom selectors
            let is_permit2_selector = matches!(
                selector,
                [0x30, 0xf2, 0x8b, 0x7a] | // permit
                [0x36, 0xc7, 0x85, 0x16] | // permitTransferFrom
                [0xed, 0xd9, 0x44, 0x4b]   // permitWitnessTransferFrom
            );

            if is_permit2_selector {
                let window = 40.min(bytecode.len().saturating_sub(pos));
                let mut has_signature = false;
                let mut has_ecrecover = false;

                // Check for signature verification
                for offset in 0..window {
                    if pos + offset < bytecode.len() {
                        match bytecode[pos + offset] {
                            0x35 => has_signature = true, // CALLDATALOAD (signature data)
                            0x01 => has_ecrecover = true, // Precompile 0x01 (ECRECOVER)
                            _ => {}
                        }
                    }
                }

                return is_permit2_selector && has_signature && has_ecrecover;
            }
        }

        false
    }

    fn has_multicall_bypass_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 60.min(bytecode.len().saturating_sub(pos));
        let lookback = 30.min(pos);
        
        let mut call_count = 1; // Current CALL
        let mut has_loop = false;
        let mut has_calldata_array = false;
        let mut delegatecall_count = 0;

        // Check for multicall pattern (loop or multiple calls)
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x57 => has_loop = true, // JUMPI (loop)
                    0x37 => has_calldata_array = true, // CALLDATACOPY (batch data)
                    _ => {}
                }
            }
        }

        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0xf1 | 0xfa => call_count += 1, // Additional CALLs
                    0xf4 => delegatecall_count += 1, // DELEGATECALL
                    _ => {}
                }
            }
        }

        // Multicall with multiple operations or loop-based execution
        (call_count >= 3 || (has_loop && call_count >= 2)) && has_calldata_array || delegatecall_count >= 1
    }

    fn has_upgradeable_proxy_bypass(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let window = 30.min(bytecode.len().saturating_sub(pos));
        
        let mut has_implementation_slot = false;
        let mut has_sload = false;
        let mut has_approval_function = false;

        // Check for EIP-1967 implementation slot pattern
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x7f => {
                        // PUSH32 - check for EIP-1967 slot
                        // 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
                        if pos >= offset + 32 {
                            let data = &bytecode[pos - offset + 1..pos - offset + 33];
                            if data[0] == 0x36 && data[1] == 0x08 {
                                has_implementation_slot = true;
                            }
                        }
                    }
                    0x54 => has_sload = true, // SLOAD (reading implementation)
                    0x63 => {
                        // Check for approval-related selectors
                        if pos >= offset + 4 {
                            let selector = &bytecode[pos - offset + 1..pos - offset + 5];
                            if selector[0] == 0x09 || selector[0] == 0xa9 {
                                has_approval_function = true;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Check for actual delegatecall execution
        let mut executes_delegatecall = false;
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if bytecode[pos + offset] == 0xf4 {
                    executes_delegatecall = true;
                    break;
                }
            }
        }

        // Upgradeable proxy with approval functions
        has_implementation_slot && has_sload && has_approval_function && executes_delegatecall
    }

    fn has_signature_aggregation_bypass(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 50.min(pos);
        let mut signature_hash_count = 1; // Current KECCAK
        let mut has_multiple_ecrecovers = false;
        let mut ecrecover_count = 0;
        let mut has_batch_verification = false;

        // Check for multiple signature verifications
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x20 => signature_hash_count += 1, // Multiple signature hashes
                    0x01 => ecrecover_count += 1, // ECRECOVER calls
                    0x57 => {
                        // JUMPI in verification loop
                        if ecrecover_count >= 2 {
                            has_batch_verification = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        if ecrecover_count >= 2 {
            has_multiple_ecrecovers = true;
        }

        // Multiple signatures being verified in batch
        signature_hash_count >= 2 && has_multiple_ecrecovers && has_batch_verification
    }
}
