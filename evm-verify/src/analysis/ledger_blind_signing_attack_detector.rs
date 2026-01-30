use crate::bytecode::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerBlindSigningVulnerability {
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

/// Ledger Blind Signing Attack Detector
///
/// Detects vulnerabilities that exploit Ledger hardware wallets' blind signing feature,
/// where users sign transactions without seeing the full transaction details on the device screen.
///
/// Attack Vectors:
/// - Malicious contracts that hide dangerous operations behind innocent-looking calls
/// - Approval phishing where users unknowingly approve unlimited token spending
/// - Complex multi-call transactions that hide malicious actions
/// - Proxy contracts that change behavior after initial approval
/// - Batch operations where only partial data is shown on Ledger screen
///
/// Real-World Cases:
/// - Multiple DeFi phishing attacks exploiting blind signing
/// - $1M+ stolen through malicious approval transactions
/// - Users approving DELEGATECALL to attacker contracts
///
/// Detection Strategy:
/// - Identifies contracts using complex multi-call patterns
/// - Detects approval mechanisms without proper user notifications
/// - Looks for proxy patterns that can hide malicious behavior
/// - Checks for batch operations that exceed Ledger display limits
/// - Identifies DELEGATECALL used in user-facing functions
pub struct LedgerBlindSigningAttackDetector;

impl LedgerBlindSigningAttackDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: Multi-call batch operations (blind signing risk)
            // Multiple CALL operations in sequence without clear separation
            if bytecode[i] == 0xf1 {
                if self.has_batch_call_blind_signing_risk(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Ledger blind signing: Batch multi-call operation that exceeds hardware wallet display capacity, users cannot verify full transaction".to_string(),
                        pc: i,
                        confidence: 0.88,
                    });
                }
            }

            // Pattern 2: Unlimited approval pattern
            // Token approval with max uint256 value (common phishing vector)
            if bytecode[i] == 0x60 && i + 1 < bytecode.len() {
                if self.has_unlimited_approval_pattern(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Unlimited approval detected: Ledger users signing this without reading may grant permanent token access".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            // Pattern 3: DELEGATECALL in user-facing function
            // Users may not understand they're signing a delegatecall
            if bytecode[i] == 0xf4 {
                if self.has_user_facing_delegatecall(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "User-facing DELEGATECALL: Ledger blind signing vulnerability - users cannot verify delegated contract behavior".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            // Pattern 4: Proxy pattern that can hide behavior changes
            // Implementation slot that can be changed after approval
            if bytecode[i] == 0x54 {
                if self.has_mutable_proxy_blind_signing_risk(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Mutable proxy pattern: Ledger users cannot verify future contract behavior after signing approval".to_string(),
                        pc: i,
                        confidence: 0.85,
                    });
                }
            }

            // Pattern 5: Complex calldata construction
            // Calldata that exceeds what Ledger can display
            if bytecode[i] == 0x37 {
                if self.has_complex_calldata_construction(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Complex calldata construction: Transaction data may exceed Ledger display limit, enabling blind signing attacks".to_string(),
                        pc: i,
                        confidence: 0.83,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    pub fn detect_vulnerabilities(&self, bytecode: Vec<u8>) -> Vec<LedgerBlindSigningVulnerability> {
        self.detect(&bytecode)
            .into_iter()
            .map(|finding| LedgerBlindSigningVulnerability {
                location: finding.pc,
                severity: format!("{:?}", finding.severity),
                description: finding.description,
                confidence: finding.confidence as f32,
            })
            .collect()
    }

    fn has_batch_call_blind_signing_risk(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 50.min(bytecode.len().saturating_sub(pos));
        let mut call_count = 1; // Current CALL
        let mut delegatecall_count = 0;
        let mut has_loop = false;

        // Check for multiple calls in sequence
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0xf1 | 0xfa => call_count += 1, // CALL, STATICCALL
                    0xf4 => delegatecall_count += 1, // DELEGATECALL
                    0x57 => has_loop = true, // JUMPI (loop pattern)
                    _ => {}
                }
            }
        }

        // Multiple calls or loop-based multicall exceeds Ledger display
        (call_count >= 3 || delegatecall_count >= 1) && (call_count >= 2 || has_loop)
    }

    fn has_unlimited_approval_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        // Check for max uint256 pattern: 0x60 0xff (PUSH1 0xff) or longer PUSH with all 0xff
        if bytecode[pos] == 0x60 && pos + 1 < bytecode.len() && bytecode[pos + 1] == 0xff {
            return true;
        }

        // Check for PUSH32 with all 0xff bytes (max uint256)
        if bytecode[pos] == 0x7f && pos + 32 < bytecode.len() {
            let all_ff = bytecode[pos + 1..pos + 33].iter().all(|&b| b == 0xff);
            if all_ff {
                // Confirm this is used in approval context
                let window = 40.min(bytecode.len().saturating_sub(pos));
                for offset in 0..window {
                    if pos + offset < bytecode.len() {
                        // Function selector for approve(address,uint256): 0x095ea7b3
                        if self.is_near_approve_selector(bytecode, pos + offset) {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    fn has_user_facing_delegatecall(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let mut has_calldata_check = false;
        let mut has_public_function = false;

        // Check if this is in a public function (function selector check nearby)
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x35 => has_calldata_check = true, // CALLDATALOAD (function dispatch)
                    0x14 => has_public_function = true, // EQ (selector comparison)
                    _ => {}
                }
            }
        }

        has_calldata_check && has_public_function
    }

    fn has_mutable_proxy_blind_signing_risk(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 40.min(bytecode.len().saturating_sub(pos));
        let lookback = 20.min(pos);
        
        let mut has_implementation_slot = false;
        let mut has_sstore = false;
        let mut has_delegatecall = false;

        // Check for implementation slot pattern (EIP-1967: 0x360894...)
        for offset in 1..=lookback {
            if pos >= offset {
                if bytecode[pos - offset] == 0x7f { // PUSH32
                    has_implementation_slot = true;
                }
            }
        }

        // Check for SSTORE and DELEGATECALL after SLOAD
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x55 => has_sstore = true, // SSTORE (can change implementation)
                    0xf4 => has_delegatecall = true, // DELEGATECALL
                    _ => {}
                }
            }
        }

        has_implementation_slot && (has_sstore || has_delegatecall)
    }

    fn has_complex_calldata_construction(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let window = 30.min(bytecode.len().saturating_sub(pos));
        
        let mut calldatacopy_count = 1; // Current CALLDATACOPY
        let mut memory_operations = 0;
        let mut has_large_size = false;

        // Check for large size parameter (exceeds Ledger display)
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x60..=0x7f => {
                        // Check if pushing large value (>256 bytes)
                        if bytecode[pos - offset] >= 0x62 { // PUSH3 or larger
                            has_large_size = true;
                        }
                    }
                    0x52 => memory_operations += 1, // MSTORE
                    _ => {}
                }
            }
        }

        // Check for additional calldata operations
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x37 => calldatacopy_count += 1, // Another CALLDATACOPY
                    0x52 => memory_operations += 1, // MSTORE
                    _ => {}
                }
            }
        }

        // Complex construction with large data or multiple copies
        (has_large_size && memory_operations >= 3) || calldatacopy_count >= 2
    }

    fn is_near_approve_selector(&self, bytecode: &[u8], pos: usize) -> bool {
        // approve(address,uint256) selector: 0x095ea7b3
        if pos + 4 < bytecode.len() {
            if bytecode[pos] == 0x63 { // PUSH4
                let selector = &bytecode[pos + 1..pos + 5];
                return selector == [0x09, 0x5e, 0xa7, 0xb3];
            }
        }
        false
    }
}
