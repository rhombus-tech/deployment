use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageAccessRulesViolation {
    pub location: usize,
    pub violation_type: StorageViolationType,
    pub severity: String,
    pub description: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageViolationType {
    ForbiddenExternalStorageAccess,  // Access external contract storage
    UnassociatedStorageAccess,       // Access storage unrelated to account
    EntityThrottlingBypass,          // Bypass entity throttling via storage
    CrossAccountStorageAccess,       // Access another account's storage
    PaymasterStorageViolation,       // Paymaster accesses forbidden storage
    FactoryStorageViolation,         // Factory accesses forbidden storage
}

pub struct StorageAccessRulesViolationDetector {
    bytecode: Vec<u8>,
}

impl StorageAccessRulesViolationDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<StorageAccessRulesViolation> {
        let mut vulnerabilities = Vec::new();

        if let Some(loc) = self.detect_external_storage_access() {
            vulnerabilities.push(StorageAccessRulesViolation {
                location: loc,
                violation_type: StorageViolationType::ForbiddenExternalStorageAccess,
                severity: "Critical".to_string(),
                description: "ERC-4337 violation: validateUserOp accesses external contract storage. \
                             Per ERC-4337, validation can only access storage associated with the \
                             account/paymaster. This creates simulation/execution divergence.".to_string(),
                confidence: 0.93,
            });
        }

        if let Some(loc) = self.detect_unassociated_storage_access() {
            vulnerabilities.push(StorageAccessRulesViolation {
                location: loc,
                violation_type: StorageViolationType::UnassociatedStorageAccess,
                severity: "High".to_string(),
                description: "Storage access to slot not associated with account address. ERC-4337 \
                             requires all storage accessed during validation must be keyed by the \
                             sender address.".to_string(),
                confidence: 0.89,
            });
        }

        if let Some(loc) = self.detect_entity_throttling_bypass() {
            vulnerabilities.push(StorageAccessRulesViolation {
                location: loc,
                violation_type: StorageViolationType::EntityThrottlingBypass,
                severity: "High".to_string(),
                description: "Storage pattern allows bypassing per-entity throttling rules. Multiple \
                             accounts can share storage to circumvent bundler rate limits.".to_string(),
                confidence: 0.87,
            });
        }

        if let Some(loc) = self.detect_cross_account_storage() {
            vulnerabilities.push(StorageAccessRulesViolation {
                location: loc,
                violation_type: StorageViolationType::CrossAccountStorageAccess,
                severity: "Critical".to_string(),
                description: "Validation accesses storage belonging to other accounts, violating \
                             ERC-4337 storage isolation requirements. Creates DoS vector.".to_string(),
                confidence: 0.91,
            });
        }

        if let Some(loc) = self.detect_paymaster_storage_violation() {
            vulnerabilities.push(StorageAccessRulesViolation {
                location: loc,
                violation_type: StorageViolationType::PaymasterStorageViolation,
                severity: "Critical".to_string(),
                description: "Paymaster validatePaymasterUserOp accesses forbidden storage slots. \
                             Only allowed to access storage associated with paymaster context.".to_string(),
                confidence: 0.90,
            });
        }

        if let Some(loc) = self.detect_factory_storage_violation() {
            vulnerabilities.push(StorageAccessRulesViolation {
                location: loc,
                violation_type: StorageViolationType::FactoryStorageViolation,
                severity: "High".to_string(),
                description: "Factory contract accesses storage during account creation that violates \
                             ERC-4337 rules. Factory must only access init-specific storage.".to_string(),
                confidence: 0.86,
            });
        }

        vulnerabilities
    }

    fn detect_external_storage_access(&self) -> Option<usize> {
        // EXTCODESIZE/EXTCODEHASH followed by SLOAD on external address
        for i in 0..self.bytecode.len().saturating_sub(15) {
            if self.bytecode[i] == 0x3b || self.bytecode[i] == 0x3f { // EXTCODESIZE or EXTCODEHASH
                // Check for SLOAD within next 10 instructions
                for j in i + 1..std::cmp::min(i + 10, self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 { // SLOAD
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_unassociated_storage_access(&self) -> Option<usize> {
        // SLOAD with constant slot not derived from sender address
        // Pattern: PUSH32(constant) SLOAD without CALLER being part of key derivation
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x7f && i + 32 < self.bytecode.len() { // PUSH32
                if i + 33 < self.bytecode.len() && self.bytecode[i + 33] == 0x54 { // SLOAD
                    // Check if CALLER was used in key derivation
                    let mut has_caller = false;
                    for j in i.saturating_sub(20)..i {
                        if self.bytecode[j] == 0x33 { // CALLER
                            has_caller = true;
                            break;
                        }
                    }
                    if !has_caller {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_entity_throttling_bypass(&self) -> Option<usize> {
        // Multiple accounts accessing same storage slot
        // Pattern: SLOAD with shared storage pattern (not sender-specific)
        let mut storage_accesses = 0;
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0x54 { // SLOAD
                storage_accesses += 1;
            }
        }
        
        // If many SLOADs without sender derivation, likely shared storage
        if storage_accesses > 5 {
            for i in 0..self.bytecode.len().saturating_sub(35) {
                if self.bytecode[i] == 0x54 { // SLOAD
                    // Check if sender-derived
                    let mut is_sender_derived = false;
                    for j in i.saturating_sub(25)..i {
                        if self.bytecode[j] == 0x33 { // CALLER
                            is_sender_derived = true;
                            break;
                        }
                    }
                    if !is_sender_derived {
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_cross_account_storage(&self) -> Option<usize> {
        // SLOAD using address from calldata/memory not associated with sender
        for i in 0..self.bytecode.len().saturating_sub(10) {
            if self.bytecode[i] == 0x35 { // CALLDATALOAD
                // Check if loaded data is used as storage key
                for j in i + 1..std::cmp::min(i + 8, self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 { // SLOAD
                        return Some(i);
                    }
                }
            }
        }
        None
    }

    fn detect_paymaster_storage_violation(&self) -> Option<usize> {
        // validatePaymasterUserOp with forbidden storage access
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i + 1],
                    self.bytecode[i + 2],
                    self.bytecode[i + 3],
                    self.bytecode[i + 4],
                ]);
                // validatePaymasterUserOp: 0xf465c77e
                if selector == 0xf465c77e {
                    // Check for SLOAD without context validation
                    for j in i..std::cmp::min(i + 25, self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 { // SLOAD
                            // Check if context-derived
                            let mut has_context = false;
                            for k in j.saturating_sub(20)..j {
                                if self.bytecode[k] == 0x30 { // ADDRESS (paymaster context)
                                    has_context = true;
                                    break;
                                }
                            }
                            if !has_context {
                                return Some(i);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn detect_factory_storage_violation(&self) -> Option<usize> {
        // Factory with non-deterministic storage access during creation
        for i in 0..self.bytecode.len().saturating_sub(20) {
            // CREATE2 followed by SLOAD
            if self.bytecode[i] == 0xf5 { // CREATE2
                for j in i + 1..std::cmp::min(i + 15, self.bytecode.len()) {
                    if self.bytecode[j] == 0x54 { // SLOAD
                        return Some(i);
                    }
                }
            }
        }
        None
    }
}
