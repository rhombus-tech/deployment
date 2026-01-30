use crate::bytecode::{SecurityFinding, SecuritySeverity};

/// Address Poisoning Attack Detector
///
/// Detects patterns that enable address poisoning attacks where attackers
/// create similar-looking addresses to trick users into sending funds to wrong addresses.
///
/// Attack Vector: Generate addresses similar to target, appear in transaction history
/// Impact: User sends funds to attacker's address thinking it's legitimate
/// Risk: Critical for wallet UIs and transaction history displays
///
/// Detection Strategy:
/// - Identifies contracts vulnerable to address confusion
/// - Detects missing address validation and checksums
/// - Checks for contracts accepting transfers without address verification
/// - Looks for vanity address generation vulnerabilities
pub struct AddressPoisoningAttackDetector;

impl AddressPoisoningAttackDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self, bytecode: &[u8]) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        let mut i = 0;

        while i < bytecode.len() {
            // Pattern 1: Transfer without address checksum validation
            if self.is_external_call(bytecode[i]) {
                if self.has_no_address_validation(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Transfer without address validation: Vulnerable to address poisoning via similar addresses".to_string(),
                        pc: i,
                        confidence: 0.81,
                    });
                }
            }

            // Pattern 2: Address comparison without full validation
            if bytecode[i] == 0x14 {
                if self.has_weak_address_comparison(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Weak address comparison: Partial address matching enables poisoning attacks".to_string(),
                        pc: i,
                        confidence: 0.78,
                    });
                }
            }

            // Pattern 3: Recipient list without checksumming
            if bytecode[i] == 0x35 {
                if self.has_unchecked_recipient_list(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Unchecked recipient addresses: Batch operations vulnerable to address poisoning".to_string(),
                        pc: i,
                        confidence: 0.84,
                    });
                }
            }

            // Pattern 4: Event logging with unvalidated addresses
            if self.is_log_operation(bytecode[i]) {
                if self.has_unvalidated_address_in_event(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::Medium,
                        description: "Event with unvalidated address: Transaction history can be poisoned with similar addresses".to_string(),
                        pc: i,
                        confidence: 0.76,
                    });
                }
            }

            // Pattern 5: Allowance/approval without address verification
            if bytecode[i] == 0x55 {
                if self.has_approval_without_address_check(bytecode, i) {
                    findings.push(SecurityFinding {
                        severity: SecuritySeverity::High,
                        description: "Approval without address validation: Spender address vulnerable to poisoning confusion".to_string(),
                        pc: i,
                        confidence: 0.83,
                    });
                }
            }

            i += 1;
        }

        findings
    }

    fn is_external_call(&self, opcode: u8) -> bool {
        matches!(opcode, 0xf1 | 0xf2 | 0xf4) // CALL/CALLCODE/DELEGATECALL
    }

    fn is_log_operation(&self, opcode: u8) -> bool {
        matches!(opcode, 0xa0..=0xa4) // LOG0 through LOG4
    }

    fn has_no_address_validation(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let mut has_address = false;
        let mut has_checksum = false;
        let mut has_zero_check = false;
        let mut has_length_check = false;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x73 => has_address = true, // PUSH20 (address)
                    0x35 => has_address = true, // CALLDATALOAD (address from input)
                    0x20 => has_checksum = true, // KECCAK256 (checksum validation)
                    0x15 => has_zero_check = true, // ISZERO (zero address check)
                    0x3b => has_length_check = true, // EXTCODESIZE (contract check)
                    _ => {}
                }
            }
        }

        // Address used but no proper validation (zero check alone insufficient)
        has_address && !has_checksum && !has_length_check
    }

    fn has_weak_address_comparison(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 30.min(pos);
        let mut has_partial_match = false;
        let mut has_mask = false;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x16 => has_mask = true, // AND (masking address)
                    0x1c | 0x1d => has_partial_match = true, // SHR/SHL (partial comparison)
                    0x60..=0x62 => {
                        // PUSH1-PUSH3 with small values (partial mask)
                        if pos >= offset + 1 && bytecode[pos - offset + 1] < 0xff {
                            has_partial_match = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Using masked or partial address comparison (vulnerable to similar addresses)
        has_partial_match || (has_mask && !self.has_full_address_comparison(bytecode, pos))
    }

    fn has_full_address_comparison(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 25.min(pos);
        
        for offset in 1..=lookback {
            if pos >= offset && bytecode[pos - offset] == 0x73 {
                // PUSH20 indicates full address comparison
                return true;
            }
        }
        false
    }

    fn has_unchecked_recipient_list(&self, bytecode: &[u8], pos: usize) -> bool {
        let window = 50.min(bytecode.len().saturating_sub(pos));
        let mut has_array = false;
        let mut has_loop = false;
        let mut has_validation = false;
        let mut has_transfer = false;

        for offset in 0..window {
            if pos + offset < bytecode.len() {
                match bytecode[pos + offset] {
                    0x5b => has_loop = true, // JUMPDEST (loop)
                    0x01 | 0x02 => has_array = true, // ADD/MUL (array indexing)
                    0xf1 => has_transfer = true, // CALL (transfer)
                    0x20 => has_validation = true, // KECCAK256 (checksum)
                    0x3b => has_validation = true, // EXTCODESIZE (validation)
                    _ => {}
                }
            }
        }

        // Array of addresses in loop without validation
        has_array && has_loop && has_transfer && !has_validation
    }

    fn has_unvalidated_address_in_event(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 35.min(pos);
        let mut has_address = false;
        let mut has_validation = false;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x73 => has_address = true, // PUSH20
                    0x35 => has_address = true, // CALLDATALOAD
                    0x20 => has_validation = true, // KECCAK256
                    0x14 => {
                        // EQ - check if comparing full address
                        if self.has_full_address_comparison(bytecode, pos - offset) {
                            has_validation = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // Event emits address without validation
        has_address && !has_validation
    }

    fn has_approval_without_address_check(&self, bytecode: &[u8], pos: usize) -> bool {
        let lookback = 40.min(pos);
        let mut has_spender = false;
        let mut has_approval_pattern = false;
        let mut has_validation = false;

        for offset in 1..=lookback {
            if pos >= offset {
                match bytecode[pos - offset] {
                    0x35 => has_spender = true, // CALLDATALOAD (spender address)
                    0x51 => has_approval_pattern = true, // MLOAD (approval amount)
                    0x15 => {
                        // ISZERO - check if it's zero address validation
                        has_validation = true;
                    }
                    0x3b => has_validation = true, // EXTCODESIZE (contract check)
                    0x33 => {
                        // CALLER - check if comparing spender to caller
                        if pos >= offset + 2 {
                            for check in 1..3 {
                                if pos >= offset + check && bytecode[pos - offset + check] == 0x14 {
                                    has_validation = true;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Approval operation without proper spender address validation
        has_spender && has_approval_pattern && !has_validation
    }
}
