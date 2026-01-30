/// Vault Migration Attack Detector
use crate::bytecode::SecurityFinding;

pub struct VaultMigrationAttackDetector {
    bytecode: Vec<u8>,
}

impl VaultMigrationAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityFinding> {
        let mut findings = Vec::new();
        if let Some(location) = self.detect_vulnerability() {
            findings.push(SecurityFinding {
                severity: crate::bytecode::SecuritySeverity::Critical,
                description: format!("Vault migration attack vulnerability at PC {}", location),
                pc: location,
                confidence: 0.90,
            });
        }
        findings
    }

    fn detect_vulnerability(&self) -> Option<usize> {
        for i in 0..self.bytecode.len().saturating_sub(60) {
            if self.check_migration_attack(i) {
                return Some(i);
            }
        }
        None
    }

    fn check_migration_attack(&self, pos: usize) -> bool {
        if pos >= self.bytecode.len() { return false; }
        
        // Check for vault migration without proper share price protection
        if pos + 4 < self.bytecode.len() && self.bytecode[pos] == 0x63 {
            // migrate, migrateToNewStrategy, setStrategy selectors
            if matches!(self.bytecode[pos+1], 0x8f | 0xd5 | 0xe6 | 0xf1) {
                let mut has_price_check = false;
                let mut has_timelock = false;
                let mut has_total_assets_validation = false;
                
                if pos + 55 < self.bytecode.len() {
                    // Check for share price validation (division + comparison)
                    for j in (pos + 5)..(pos + 35).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x04 && j + 8 < self.bytecode.len() { // DIV
                            if (self.bytecode[j + 4] == 0x10 || self.bytecode[j + 4] == 0x11) && 
                               matches!(self.bytecode[j + 6], 0x57 | 0xfd) {
                                has_price_check = true;
                            }
                        }
                    }
                    
                    // Check for timelock (TIMESTAMP comparison)
                    for j in (pos + 5)..(pos + 40).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x42 && j + 6 < self.bytecode.len() { // TIMESTAMP
                            if (self.bytecode[j + 3] == 0x10 || self.bytecode[j + 3] == 0x11) &&
                               matches!(self.bytecode[j + 5], 0x57 | 0xfd) {
                                has_timelock = true;
                            }
                        }
                    }
                    
                    // Check for total assets validation before and after
                    let mut asset_reads = 0;
                    for j in (pos + 5)..(pos + 55).min(self.bytecode.len()) {
                        if self.bytecode[j] == 0x54 { // SLOAD (reading balances)
                            asset_reads += 1;
                        }
                    }
                    if asset_reads >= 2 {
                        has_total_assets_validation = true;
                    }
                }
                
                // Vulnerable if migration without proper protections
                return !has_price_check || !has_timelock || !has_total_assets_validation;
            }
        }
        false
    }
}
