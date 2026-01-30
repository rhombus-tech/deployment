use crate::bytecode::SecurityFinding;

pub struct AccountBoundTokenDetector {
    bytecode: Vec<u8>,
}

impl AccountBoundTokenDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<SecurityFinding> {
        self.detect()
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_soulbound_transfer_bypass() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Account-bound token transfer restrictions can be bypassed at PC {}. \
                    Soulbound tokens can be transferred defeating their purpose.",
                    pc
                ),
                pc,
                confidence: 0.93,
            });
        }

        if let Some(pc) = self.detect_delegation_exploit() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Account-bound token delegation mechanism exploitable at PC {}. \
                    Tokens can be used by unauthorized accounts through delegation loopholes.",
                    pc
                ),
                pc,
                confidence: 0.89,
            });
        }

        if let Some(pc) = self.detect_recovery_mechanism_abuse() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Token recovery mechanism can be abused at PC {}. \
                    Account recovery allows unauthorized token transfers.",
                    pc
                ),
                pc,
                confidence: 0.87,
            });
        }

        findings
    }

    fn detect_soulbound_transfer_bypass(&self) -> Option<usize> {
        // Look for transfer functions that should be disabled but aren't
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // transfer, transferFrom, safeTransferFrom selectors
                if matches!(selector, [0xa9, 0x05, 0x9c, 0xbb] | [0x23, 0xb8, 0x72, 0xdd] | [0x42, 0x84, 0x2e, 0x0e]) {
                    let mut has_soulbound_check = false;
                    let mut always_reverts = false;
                    let mut checks_exceptions = false;
                    
                    for j in i..i.saturating_add(60).min(self.bytecode.len()) {
                        // Check for soulbound flag
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (soulbound flag)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x15 && // ISZERO
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x57 { // JUMPI (revert if soulbound)
                                has_soulbound_check = true;
                            }
                        }
                        // Check if function always reverts
                        if j + 4 < self.bytecode.len() {
                            if self.bytecode[j] == 0xfd { // REVERT
                                // Check if there's conditional logic before revert
                                let mut has_conditional = false;
                                for k in i..j {
                                    if self.bytecode[k] == 0x57 { // JUMPI
                                        has_conditional = true;
                                        break;
                                    }
                                }
                                if !has_conditional {
                                    always_reverts = true;
                                }
                            }
                        }
                        // Check for exceptions (admin transfers, burns)
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x33 && // CALLER
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x54 && // SLOAD (admin)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x14 { // EQ
                                checks_exceptions = true;
                            }
                        }
                    }
                    
                    // Flag if transfer function exists without proper soulbound enforcement
                    if !has_soulbound_check && !always_reverts {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_delegation_exploit(&self) -> Option<usize> {
        // Look for approval/delegation mechanisms in soulbound tokens
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // approve, setApprovalForAll, delegate selectors
                if matches!(selector, [0x09, 0x5e, 0xa7, 0xb3] | [0xa2, 0x2c, 0xb4, 0x65] | [0x5c, 0x19, 0xa9, 0x5c]) {
                    let mut blocks_delegation = false;
                    let mut validates_soulbound = false;
                    let mut restricts_operations = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check if delegation is blocked
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x60 && // PUSH1 0x00
                               self.bytecode[j + 1] == 0x00 &&
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0xfd { // REVERT
                                blocks_delegation = true;
                            }
                        }
                        // Check for soulbound validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (soulbound status)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x15 { // ISZERO
                                validates_soulbound = true;
                            }
                        }
                        // Check for operation restrictions
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (operator)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x33 && // CALLER (owner)
                               j + 7 < self.bytecode.len() &&
                               self.bytecode[j + 6] == 0x14 { // EQ (checking owner == operator)
                                restricts_operations = true;
                            }
                        }
                    }
                    
                    if !blocks_delegation && !validates_soulbound {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_recovery_mechanism_abuse(&self) -> Option<usize> {
        // Look for account recovery that allows token movement
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // recover, reclaim, migrateAccount selectors
                if matches!(selector, [0xd1, 0x3e, _, _] | [0xe2, 0x4f, _, _] | [0xf3, 0x5c, _, _]) {
                    let mut has_proof_verification = false;
                    let mut validates_time_lock = false;
                    let mut requires_multi_sig = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check for cryptographic proof verification
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x60 && // PUSH1 0x01 (ecrecover)
                               self.bytecode[j + 1] == 0x01 &&
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0xfa { // STATICCALL
                                has_proof_verification = true;
                            }
                        }
                        // Check for time lock
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x42 && // TIMESTAMP
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x03 && // SUB
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x10 { // LT (checking time passed)
                                validates_time_lock = true;
                            }
                        }
                        // Check for multi-sig requirement
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (approval count)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x10 && // LT (checking threshold)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x15 { // ISZERO
                                requires_multi_sig = true;
                            }
                        }
                    }
                    
                    if !has_proof_verification && !validates_time_lock && !requires_multi_sig {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
