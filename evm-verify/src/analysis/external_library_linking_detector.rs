use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity};
use ethers::types::U256;

/// External Library Linking Exploits Detector
/// 
/// Detects vulnerabilities where external library dependencies can be exploited
/// through unlinking, self-destruction, or malicious replacement.
/// 
/// **Attack Patterns**:
/// 1. **Library Unlinking**: Remove library causing contract to fail or behave unexpectedly
/// 2. **Library Selfdestruct**: Destroy library contract, breaking dependent contracts
/// 3. **Library Replacement**: Replace library with malicious implementation
/// 4. **Uninitialized Library**: Use library before proper initialization
/// 5. **Delegatecall to Destructed Library**: DELEGATECALL to destroyed library address
/// 
/// **Historical Context**:
/// Parity Wallet hack ($280M+) involved library self-destruction affecting dependent contracts.
/// Similar patterns can occur with any external library dependency.
/// 
/// **Detection Strategy**:
/// - Identifies DELEGATECALL to external addresses without existence checks
/// - Detects library addresses that can be changed without validation
/// - Flags missing checks for library initialization
/// - Checks for library self-destruct protection
/// - Validates library upgrade mechanisms
pub struct ExternalLibraryLinkingDetector {
    bytecode: Vec<u8>,
}

impl ExternalLibraryLinkingDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect(&self) -> Vec<SecurityWarning> {
        let mut warnings = Vec::new();

        if self.has_delegatecall_without_existence_check() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::UncheckedExternalCall,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "DELEGATECALL to library without checking if code exists - Parity-style vulnerability".to_string(),
                operations: Vec::new(),
                remediation: "Add EXTCODESIZE check before DELEGATECALL to ensure library exists".to_string(),
            });
        }

        if self.has_mutable_library_address() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::AccessControl,
                severity: SecuritySeverity::Critical,
                pc: 0,
                description: "Library address can be changed, allowing malicious library replacement".to_string(),
                operations: Vec::new(),
                remediation: "Make library addresses immutable or require timelock + multi-sig for changes".to_string(),
            });
        }

        if self.has_uninitialized_library_usage() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Library functions called without verifying library initialization".to_string(),
                operations: Vec::new(),
                remediation: "Add initialization checks before library function calls".to_string(),
            });
        }

        if self.has_library_selfdestruct_risk() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::LogicError,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Library contract contains SELFDESTRUCT without protection".to_string(),
                operations: Vec::new(),
                remediation: "Remove SELFDESTRUCT from library or add strict access controls".to_string(),
            });
        }

        if self.has_unsafe_library_upgrade() {
            warnings.push(SecurityWarning {
                kind: SecurityWarningKind::AccessControl,
                severity: SecuritySeverity::High,
                pc: 0,
                description: "Library upgrade mechanism lacks proper validation and security".to_string(),
                operations: Vec::new(),
                remediation: "Implement secure upgrade pattern with validation and timelock".to_string(),
            });
        }

        warnings
    }

    fn has_delegatecall_without_existence_check(&self) -> bool {
        // Pattern: DELEGATECALL to address without EXTCODESIZE check
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.bytecode[i] == 0xf4 { // DELEGATECALL
                let window = &self.bytecode[i.saturating_sub(25)..i];
                
                // Check if target address comes from storage (library address)
                let has_storage_address = window.iter().any(|&op| {
                    op == 0x54 // SLOAD (load library address)
                });
                
                // Check for EXTCODESIZE validation before call
                let has_code_check = window.windows(6).any(|w| {
                    // Pattern: DUP(address) -> EXTCODESIZE -> ISZERO -> REVERT
                    w.iter().any(|&op| op >= 0x80 && op <= 0x8f) && // DUP
                    w.iter().any(|&op| op == 0x3b) && // EXTCODESIZE
                    w.iter().any(|&op| op == 0x15) && // ISZERO
                    w.iter().any(|&op| op == 0xfd) // REVERT if no code
                });
                
                // Check for existence validation via STATICCALL test
                let has_call_test = window.windows(5).any(|w| {
                    w.iter().any(|&op| op == 0xfa) && // STATICCALL (test call)
                    w.iter().any(|&op| op == 0x15) // ISZERO (check result)
                });
                
                if has_storage_address && !has_code_check && !has_call_test {
                    return true;
                }
            }
        }
        false
    }

    fn has_mutable_library_address(&self) -> bool {
        // Pattern: setLibrary() or updateLibrary() without proper protection
        let set_library = [0x7b, 0x10, 0x39, 0x9e]; // setLibrary()
        let update_library = [0xc4, 0x8d, 0xd7, 0x70]; // updateLibrary()
        
        for i in 0..self.bytecode.len().saturating_sub(40) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == set_library || selector == update_library {
                    let window = &self.bytecode[i..i+40.min(self.bytecode.len())];
                    
                    // Check for library address storage
                    let has_library_storage = window.contains(&0x55); // SSTORE
                    
                    // Check for immutability (should not allow changes after init)
                    let has_immutable_check = window.windows(6).any(|w| {
                        // Pattern: SLOAD(library) -> ISZERO (check if already set) -> JUMPI
                        w.iter().any(|&op| op == 0x54) && // SLOAD
                        w.iter().any(|&op| op == 0x15) && // ISZERO
                        w.iter().any(|&op| op == 0xfd) // REVERT if already set
                    });
                    
                    // Check for timelock
                    let has_timelock = window.windows(8).any(|w| {
                        w.iter().any(|&op| op == 0x42) && // TIMESTAMP
                        w.iter().any(|&op| op == 0x54) && // SLOAD (proposed time)
                        w.iter().any(|&op| op == 0x10) // LT (time check)
                    });
                    
                    // Check for code validation
                    let has_code_validation = window.windows(4).any(|w| {
                        w.iter().any(|&op| op == 0x3b) && // EXTCODESIZE
                        w.iter().any(|&op| op == 0x11) // GT (size > 0)
                    });
                    
                    if has_library_storage && !has_immutable_check && !has_timelock && !has_code_validation {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn has_uninitialized_library_usage(&self) -> bool {
        // Pattern: DELEGATECALL before checking if library is initialized
        for i in 0..self.bytecode.len().saturating_sub(25) {
            if self.bytecode[i] == 0xf4 { // DELEGATECALL
                let window = &self.bytecode[i.saturating_sub(20)..i];
                
                // Check if library address comes from storage
                let has_library_load = window.iter().any(|&op| {
                    op == 0x54 // SLOAD
                });
                
                // Check for initialization validation
                let has_init_check = window.windows(5).any(|w| {
                    // Pattern: SLOAD(initialized flag) -> require(initialized)
                    w[0] == 0x54 && // SLOAD
                    w.iter().any(|&op| op == 0x15) && // ISZERO
                    w.iter().any(|&op| op == 0xfd) // REVERT if not initialized
                });
                
                // Check for non-zero address validation
                let has_address_check = window.windows(4).any(|w| {
                    w.iter().any(|&op| op == 0x15) && // ISZERO (check if address is zero)
                    w.iter().any(|&op| op == 0xfd) // REVERT if zero
                });
                
                if has_library_load && !has_init_check && !has_address_check {
                    return true;
                }
            }
        }
        false
    }

    fn has_library_selfdestruct_risk(&self) -> bool {
        // Check if contract contains SELFDESTRUCT (could be a library)
        if !self.bytecode.contains(&0xff) {
            return false; // No SELFDESTRUCT present
        }
        
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xff { // SELFDESTRUCT
                let window_before = &self.bytecode[i.saturating_sub(30)..i];
                
                // Check for strong access control before SELFDESTRUCT
                let has_strong_access_control = window_before.windows(8).any(|w| {
                    // Pattern: multi-sig or complex authorization
                    w.iter().filter(|&&op| op == 0x20).count() >= 2 && // Multiple KECCAK256 (sig checks)
                    w.iter().any(|&op| op == 0x14) // EQ (verify)
                });
                
                // Check if in constructor (acceptable for factory pattern)
                let in_constructor = window_before.windows(10).any(|w| {
                    // Pattern: CODESIZE -> CODECOPY (constructor pattern)
                    w.iter().any(|&op| op == 0x38) && // CODESIZE
                    w.iter().any(|&op| op == 0x39) // CODECOPY
                });
                
                // Check for simple owner check
                let has_simple_owner_check = window_before.windows(6).any(|w| {
                    w.iter().any(|&op| op == 0x33) && // CALLER
                    w.iter().any(|&op| op == 0x14) // EQ (check owner)
                });
                
                // Vulnerable if has SELFDESTRUCT with only simple owner check (not multi-sig)
                if !in_constructor && has_simple_owner_check && !has_strong_access_control {
                    return true;
                }
                
                // Also vulnerable if no access control at all
                if !in_constructor && !has_simple_owner_check && !has_strong_access_control {
                    return true;
                }
            }
        }
        false
    }

    fn has_unsafe_library_upgrade(&self) -> bool {
        // Pattern: upgrade function that changes library implementation
        let upgrade_selector = [0x4f, 0x1e, 0xf2, 0x86]; // upgradeTo()
        
        for i in 0..self.bytecode.len().saturating_sub(45) {
            if self.bytecode[i] == 0x63 && i + 5 < self.bytecode.len() {
                let selector = &self.bytecode[i+1..i+5];
                
                if selector == upgrade_selector {
                    let window = &self.bytecode[i..i+45.min(self.bytecode.len())];
                    
                    // Check for implementation storage update
                    let has_impl_update = window.contains(&0x55); // SSTORE
                    
                    // Check for new implementation validation
                    let has_code_validation = window.windows(5).any(|w| {
                        w.iter().any(|&op| op == 0x3b) && // EXTCODESIZE
                        w.iter().any(|&op| op == 0x11) && // GT
                        w.iter().any(|&op| op == 0x57) // JUMPI
                    });
                    
                    // Check for interface validation
                    let has_interface_check = window.windows(6).any(|w| {
                        w.iter().any(|&op| op == 0xfa) && // STATICCALL (supportsInterface)
                        w.iter().any(|&op| op == 0x15) // ISZERO (check result)
                    });
                    
                    // Check for timelock
                    let has_timelock = window.windows(8).any(|w| {
                        w.iter().any(|&op| op == 0x42) // TIMESTAMP
                    });
                    
                    if has_impl_update && !has_code_validation && !has_interface_check && !has_timelock {
                        return true;
                    }
                }
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parity_style_vulnerability() {
        let vulnerable_bytecode = vec![
            0x54, // SLOAD (load library address)
            0xf4, // DELEGATECALL (to library without existence check!)
        ];

        let detector = ExternalLibraryLinkingDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.description.contains("DELEGATECALL")));
    }

    #[test]
    fn test_library_selfdestruct() {
        let vulnerable_bytecode = vec![
            0x33, // CALLER
            0x54, // SLOAD (owner)
            0x14, // EQ (check if caller == owner)
            0x57, // JUMPI
            0xff, // SELFDESTRUCT (weak protection!)
        ];

        let detector = ExternalLibraryLinkingDetector::new(vulnerable_bytecode);
        let warnings = detector.detect();
        
        assert!(warnings.iter().any(|w| w.description.contains("SELFDESTRUCT")));
    }
}
