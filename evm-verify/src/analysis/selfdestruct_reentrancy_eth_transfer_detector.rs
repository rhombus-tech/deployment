use crate::bytecode::{SecurityFinding, SecuritySeverity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfdestructReentrancyEthVulnerability {
    pub location: usize,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

/// SELFDESTRUCT Reentrancy ETH Transfer Detector
///
/// Detects vulnerabilities where SELFDESTRUCT opcode is used in combination with reentrancy
/// to force-send ETH to contracts, bypassing receive/fallback checks and reentrancy guards.
///
/// Attack Mechanics:
/// - SELFDESTRUCT forces ETH transfer even to contracts without payable functions
/// - Reentrancy guards don't protect against SELFDESTRUCT force-feeding
/// - Contract balance checks can be manipulated via forced ETH sends
/// - SELFDESTRUCT in same transaction as external calls enables complex attacks
/// - Post-London hard fork: SELFDESTRUCT still transfers but doesn't delete in same block
///
/// Real-World Cases:
/// - King of the Ether exploit: forced ETH breaks game logic
/// - Multiple DeFi protocols with balance-based logic broken
/// - Auction contracts accepting forced ETH after closure
/// - Games with "richest player" mechanics exploited
///
/// Detection Strategy:
/// - Identifies SELFDESTRUCT with external CALLs nearby
/// - Detects balance checks that could be manipulated
/// - Looks for reentrancy patterns combined with SELFDESTRUCT
/// - Checks for contracts receiving ETH without proper validation
/// - Identifies game-theory logic dependent on balances
pub struct SelfdestructReentrancyEthTransferDetector {
    bytecode: Vec<u8>,
}

impl SelfdestructReentrancyEthTransferDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SelfdestructReentrancyEthVulnerability> {
        self.detect(&self.bytecode)
            .into_iter()
            .map(|finding| SelfdestructReentrancyEthVulnerability {
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
            // Pattern 1: SELFDESTRUCT with external CALL nearby (reentrancy risk)
            if bytecode[i] == 0xff {
                if self.has_selfdestruct_with_external_call(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "SELFDESTRUCT reentrancy: SELFDESTRUCT near external call enables forced ETH transfer bypassing reentrancy guards".to_string(),
                        pc: i,
                        confidence: 0.89,
                    });
                }
            }

            // Pattern 2: Balance check with SELFDESTRUCT (balance manipulation)
            if bytecode[i] == 0x47 {
                if self.has_balance_check_selfdestruct_risk(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Balance manipulation via SELFDESTRUCT: Contract logic depends on balance checks that can be bypassed with forced ETH".to_string(),
                        pc: i,
                        confidence: 0.87,
                    });
                }
            }

            // Pattern 3: SELFDESTRUCT without access control (public self-destruct)
            if bytecode[i] == 0xff {
                if self.has_unprotected_selfdestruct(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "Unprotected SELFDESTRUCT: Can be exploited for reentrancy attacks and forced ETH transfers".to_string(),
                        pc: i,
                        confidence: 0.88,
                    });
                }
            }

            // Pattern 4: CREATE2 + SELFDESTRUCT (metamorphic contract attack)
            if bytecode[i] == 0xf5 {
                if self.has_create2_selfdestruct_pattern(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "CREATE2 + SELFDESTRUCT: Metamorphic contract pattern enables repeated forced ETH attacks".to_string(),
                        pc: i,
                        confidence: 0.86,
                    });
                }
            }

            // Pattern 5: SELFDESTRUCT in delegatecall context (proxy self-destruct)
            if bytecode[i] == 0xf4 {
                if self.has_delegatecall_selfdestruct_risk(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Critical,
                        description: "DELEGATECALL SELFDESTRUCT: Implementation can self-destruct proxy, force ETH transfer in reentrancy attack".to_string(),
                        pc: i,
                        confidence: 0.88,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    fn has_selfdestruct_with_external_call(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 50.min(pos);
        let window = 40.min(bytecode.len().saturating_sub(pos));
        
        let mut has_external_call = false;
        let mut has_call_after = false;
        let mut has_reentrancy_pattern = false;

        // Check for external calls before SELFDESTRUCT
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0xf1 | 0xfa => has_external_call = true, // CALL, STATICCALL
                    0x54 => {
                        // SLOAD followed by SSTORE (reentrancy guard check)
                        if has_external_call {
                            has_reentrancy_pattern = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Check for calls after SELFDESTRUCT (in surrounding function logic)
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if bytecode[pos + offset] == 0xf1 || bytecode[pos + offset] == 0xfa {
                    has_call_after = true;
                    break;
                }
            }
        }

        // SELFDESTRUCT near external calls suggests reentrancy exploitation
        (has_external_call && !has_reentrancy_pattern) || has_call_after
    }

    fn has_balance_check_selfdestruct_risk(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 60.min(bytecode.len().saturating_sub(pos));
        let mut has_comparison = false;
        let mut has_selfdestruct = false;
        let mut has_conditional = false;

        // SELFBALANCE followed by comparison and SELFDESTRUCT
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x10 | 0x11 | 0x12 => has_comparison = true, // LT, GT, SLT (balance comparison)
                    0x14 => has_comparison = true, // EQ (exact balance check)
                    0x57 => has_conditional = true, // JUMPI (conditional logic)
                    0xff => has_selfdestruct = true, // SELFDESTRUCT
                    _ => {}
                }
            }
        }

        // Balance-dependent logic with SELFDESTRUCT
        has_comparison && has_conditional && has_selfdestruct
    }

    fn has_unprotected_selfdestruct(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let mut has_caller_check = false;
        let mut has_owner_check = false;
        let mut has_conditional = false;

        // Check for access control before SELFDESTRUCT
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x33 => has_caller_check = true, // CALLER
                    0x14 => {
                        // EQ with CALLER suggests owner check
                        if has_caller_check {
                            has_owner_check = true;
                        }
                    }
                    0x57 => has_conditional = true, // JUMPI (access control)
                    0xfd => {
                        // REVERT (access denied)
                        if has_owner_check {
                            has_conditional = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // SELFDESTRUCT without proper access control
        !has_owner_check || !has_conditional
    }

    fn has_create2_selfdestruct_pattern(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 80.min(bytecode.len().saturating_sub(pos));
        let mut has_selfdestruct = false;
        let mut has_init_code = false;
        let mut has_salt = false;

        // CREATE2 with SELFDESTRUCT in deployment code
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0xff => has_selfdestruct = true, // SELFDESTRUCT
                    0x39 => has_init_code = true, // CODECOPY (init code)
                    0x20 => {
                        // KECCAK256 (salt calculation)
                        if has_init_code {
                            has_salt = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Metamorphic contract pattern: CREATE2 + SELFDESTRUCT
        has_selfdestruct && has_init_code && has_salt
    }

    fn has_delegatecall_selfdestruct_risk(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 60.min(bytecode.len().saturating_sub(pos));
        let lookback = 30.min(pos);
        
        let mut has_implementation_load = false;
        let mut has_selfdestruct = false;
        let mut has_fallback = false;

        // Check for proxy pattern before DELEGATECALL
        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x54 => has_implementation_load = true, // SLOAD (implementation address)
                    0x36 => has_fallback = true, // CALLDATASIZE (fallback check)
                    _ => {}
                }
            }
        }

        // Check for SELFDESTRUCT after DELEGATECALL
        for offset in 1..window {
            if pos + offset < bytecode.len() {
                if bytecode[pos + offset] == 0xff {
                    has_selfdestruct = true;
                    break;
                }
            }
        }

        // DELEGATECALL in proxy with SELFDESTRUCT risk
        has_implementation_load && has_fallback && has_selfdestruct
    }
}
