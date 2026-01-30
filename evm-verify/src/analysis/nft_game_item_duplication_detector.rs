use crate::bytecode::SecurityFinding;

pub struct NftGameItemDuplicationDetector {
    bytecode: Vec<u8>,
}

impl NftGameItemDuplicationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();

        if let Some(pc) = self.detect_mint_without_burn_check() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Game item minting lacks uniqueness verification at PC {}. \
                    Items can be duplicated allowing infinite resource generation.",
                    pc
                ),
                pc,
                confidence: 0.92,
            });
        }

        if let Some(pc) = self.detect_crafting_duplication() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!(
                    "Item crafting vulnerable to duplication exploit at PC {}. \
                    Missing atomic burn-and-mint check allows double-spending materials.",
                    pc
                ),
                pc,
                confidence: 0.90,
            });
        }

        if let Some(pc) = self.detect_trade_reentrancy() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::High,
                description: format!(
                    "Item trading vulnerable to reentrancy duplication at PC {}. \
                    Items can be duplicated through reentrancy during transfer.",
                    pc
                ),
                pc,
                confidence: 0.88,
            });
        }

        findings
    }

    fn detect_mint_without_burn_check(&self) -> Option<usize> {
        // Look for minting without proper existence/uniqueness checks
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // mint, mintItem, createItem selectors
                if matches!(selector, [0x40, 0xc1, 0x0f, 0x19] | [0x51, 0xd2, _, _] | [0x62, 0xe3, _, _]) {
                    let mut has_existence_check = false;
                    let mut has_nonce_increment = false;
                    let mut validates_supply_cap = false;
                    
                    for j in i..i.saturating_add(70).min(self.bytecode.len()) {
                        // Check for item existence validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x35 && // CALLDATALOAD (tokenId)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x54 && // SLOAD (check if exists)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x15 { // ISZERO (must not exist)
                                has_existence_check = true;
                            }
                        }
                        // Check for nonce/counter increment
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (nonce)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x01 && // ADD (incrementing)
                               j + 5 < self.bytecode.len() &&
                               self.bytecode[j + 4] == 0x55 { // SSTORE (saving new nonce)
                                has_nonce_increment = true;
                            }
                        }
                        // Check for supply cap validation
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (total supply)
                               j + 4 < self.bytecode.len() &&
                               self.bytecode[j + 3] == 0x10 && // LT (checking below cap)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x15 { // ISZERO (require check)
                                validates_supply_cap = true;
                            }
                        }
                    }
                    
                    if !has_existence_check || !has_nonce_increment {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_crafting_duplication(&self) -> Option<usize> {
        // Look for crafting that doesn't atomically burn inputs
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // craft, combine, forge selectors
                if matches!(selector, [0x73, 0xa4, _, _] | [0x84, 0xb5, _, _] | [0x95, 0xc6, _, _]) {
                    let mut burns_materials = false;
                    let mut mints_result = false;
                    let mut has_atomic_check = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check for burn operation
                        if j + 4 < self.bytecode.len() && self.bytecode[j] == 0x63 {
                            let sub_selector = &self.bytecode[j + 1..j + 5];
                            // burn selector
                            if matches!(sub_selector, [0x42, 0x96, 0x6c, 0x68]) {
                                burns_materials = true;
                            }
                            // mint selector
                            if matches!(sub_selector, [0x40, 0xc1, 0x0f, 0x19]) {
                                mints_result = true;
                            }
                        }
                        // Check for reentrancy guard or state lock
                        if j + 8 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (reentrancy flag)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x15 && // ISZERO (checking not locked)
                               j + 6 < self.bytecode.len() &&
                               self.bytecode[j + 5] == 0x55 { // SSTORE (setting lock)
                                has_atomic_check = true;
                            }
                        }
                    }
                    
                    // Flag if minting without burning materials or without atomicity
                    if mints_result && (!burns_materials || !has_atomic_check) {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_trade_reentrancy(&self) -> Option<usize> {
        // Look for item transfers vulnerable to reentrancy
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if i + 4 < self.bytecode.len() && self.bytecode[i] == 0x63 {
                let selector = &self.bytecode[i + 1..i + 5];
                // transferFrom, safeTransferFrom, trade selectors
                if matches!(selector, [0x23, 0xb8, 0x72, 0xdd] | [0x42, 0x84, 0x2e, 0x0e] | [0xa1, 0x2e, _, _]) {
                    let mut has_reentrancy_guard = false;
                    let mut updates_balance_before_call = false;
                    let mut makes_external_call = false;
                    
                    for j in i..i.saturating_add(80).min(self.bytecode.len()) {
                        // Check for reentrancy guard
                        if j + 10 < self.bytecode.len() {
                            if self.bytecode[j] == 0x54 && // SLOAD (guard)
                               j + 3 < self.bytecode.len() &&
                               self.bytecode[j + 2] == 0x15 && // ISZERO
                               j + 8 < self.bytecode.len() &&
                               self.bytecode[j + 7] == 0x55 { // SSTORE (setting guard)
                                has_reentrancy_guard = true;
                            }
                        }
                        // Check if balance updated before external call
                        if j + 6 < self.bytecode.len() {
                            if self.bytecode[j] == 0x55 { // SSTORE (updating balance)
                                // Look for external call after this
                                for k in j..j.saturating_add(20).min(self.bytecode.len()) {
                                    if self.bytecode[k] == 0xf1 || // CALL
                                       self.bytecode[k] == 0xf4 { // DELEGATECALL
                                        updates_balance_before_call = true;
                                        break;
                                    }
                                }
                            }
                        }
                        // Check for external calls
                        if self.bytecode[j] == 0xf1 || // CALL
                           self.bytecode[j] == 0xf4 { // DELEGATECALL
                            makes_external_call = true;
                        }
                    }
                    
                    if makes_external_call && !has_reentrancy_guard && !updates_balance_before_call {
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
