use serde::{Serialize, Deserialize};

/// ERC-6900 Modular Account Security Detection
/// 
/// ERC-6900 defines a standard for modular smart contract accounts where
/// functionality can be added/removed via plugins/modules. Vulnerabilities:
/// 
/// 1. Malicious modules can hijack account control
/// 2. Module installation without proper validation
/// 3. Conflicting hooks between modules
/// 4. Module can bypass validation rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Erc6900ModuleSecurityVulnerability {
    /// Critical: Module can be installed without validation
    UnvalidatedModuleInstall {
        description: String,
        location: usize,
        confidence: f32,
    },
    /// Critical: Module has excessive permissions
    ExcessiveModulePermissions {
        description: String,
        location: usize,
    },
    /// High: No module execution constraints
    MissingExecutionConstraints {
        description: String,
        location: usize,
    },
    /// High: Conflicting module hooks
    ConflictingModuleHooks {
        description: String,
        location: usize,
    },
    /// Medium: Module uninstall doesn't cleanup state
    IncompleteModuleCleanup {
        description: String,
        location: usize,
    },
}

pub struct Erc6900ModuleSecurityDetector {
    bytecode: Vec<u8>,
}

impl Erc6900ModuleSecurityDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Erc6900ModuleSecurityVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Check installModule/addModule functions
        // ERC-6900: installPlugin selector patterns
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2],
                    self.bytecode[i+3], self.bytecode[i+4],
                ]);
                
                // Check if this is a module installation function
                if self.is_module_install_function(i) {
                    // Verify module validation exists
                    let has_validation = self.validates_module_code(i);
                    
                    if !has_validation {
                        vulnerabilities.push(Erc6900ModuleSecurityVulnerability::UnvalidatedModuleInstall {
                            description: format!(
                                "Module install function (0x{:08x}) without code validation",
                                selector
                            ),
                            location: i,
                            confidence: 0.90,
                        });
                    }
                    
                    // Check if module interface is verified
                    let verifies_interface = self.verifies_module_interface(i);
                    
                    if !verifies_interface {
                        vulnerabilities.push(Erc6900ModuleSecurityVulnerability::UnvalidatedModuleInstall {
                            description: "Module install without ERC-165 interface verification".to_string(),
                            location: i,
                            confidence: 0.85,
                        });
                    }
                }
            }
        }
        
        // Pattern 2: Check module execution permissions
        // Modules should have limited execution context
        for i in 0..self.bytecode.len().saturating_sub(80) {
            // Look for DELEGATECALL to modules (dangerous!)
            if self.bytecode[i] == 0xf4 { // DELEGATECALL
                // Check if this delegates to a module
                let delegates_to_module = self.is_module_delegation(i);
                
                if delegates_to_module {
                    // Check for permission boundaries
                    let has_permission_check = self.has_permission_boundaries(i);
                    
                    if !has_permission_check {
                        vulnerabilities.push(Erc6900ModuleSecurityVulnerability::ExcessiveModulePermissions {
                            description: "DELEGATECALL to module without permission boundaries - full account control".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 3: Check execution hooks
        // Pre/post execution hooks must be properly managed
        for i in 0..self.bytecode.len().saturating_sub(70) {
            // Look for hook execution patterns
            if self.is_hook_execution(i) {
                // Check for hook ordering/conflict resolution
                let handles_conflicts = self.handles_hook_conflicts(i);
                
                if !handles_conflicts {
                    vulnerabilities.push(Erc6900ModuleSecurityVulnerability::ConflictingModuleHooks {
                        description: "Module hooks executed without conflict resolution".to_string(),
                        location: i,
                    });
                }
                
                // Check for hook gas limits
                let has_gas_limit = self.has_hook_gas_limit(i);
                
                if !has_gas_limit {
                    vulnerabilities.push(Erc6900ModuleSecurityVulnerability::MissingExecutionConstraints {
                        description: "Module hook without gas limit - can DoS account".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 4: Check uninstallModule function
        for i in 0..self.bytecode.len().saturating_sub(90) {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() {
                let selector = u32::from_be_bytes([
                    self.bytecode[i+1], self.bytecode[i+2],
                    self.bytecode[i+3], self.bytecode[i+4],
                ]);
                
                if self.is_module_uninstall_function(i) {
                    // Check if state is properly cleaned up
                    let cleans_up_state = self.properly_cleans_module_state(i);
                    
                    if !cleans_up_state {
                        vulnerabilities.push(Erc6900ModuleSecurityVulnerability::IncompleteModuleCleanup {
                            description: format!(
                                "Module uninstall (0x{:08x}) doesn't cleanup state - zombie permissions",
                                selector
                            ),
                            location: i,
                        });
                    }
                }
            }
        }
        
        // Pattern 5: Check for module validation rules
        // ERC-6900 requires validation phase before execution
        for i in 0..self.bytecode.len().saturating_sub(100) {
            // Look for validation function patterns
            if self.is_validation_function(i) {
                // Check if validation can be bypassed
                let can_be_bypassed = self.validation_can_be_bypassed(i);
                
                if can_be_bypassed {
                    vulnerabilities.push(Erc6900ModuleSecurityVulnerability::MissingExecutionConstraints {
                        description: "Module validation can be bypassed - execution without checks".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 6: Check module storage isolation
        // Modules should have isolated storage to prevent conflicts
        for i in 0..self.bytecode.len().saturating_sub(60) {
            // Look for module storage access patterns
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check if storage slot is namespaced/isolated
                let is_isolated = self.uses_isolated_storage(i);
                
                if !is_isolated {
                    // Check if this is in module context
                    let in_module_context = self.is_in_module_context(i);
                    
                    if in_module_context {
                        vulnerabilities.push(Erc6900ModuleSecurityVulnerability::ConflictingModuleHooks {
                            description: "Module uses non-isolated storage - can conflict with other modules".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn is_module_install_function(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 100, self.bytecode.len());
        let section = &self.bytecode[location..end];
        
        // Install function typically:
        // 1. Takes module address as parameter
        // 2. Stores it (SSTORE)
        // 3. May emit event (LOG)
        
        let has_address_param = section.iter().any(|&b| b == 0x35); // CALLDATALOAD
        let stores_address = section.iter().any(|&b| b == 0x55); // SSTORE
        let may_emit = section.iter().any(|&b| b == 0xa0 || b == 0xa1); // LOG0 or LOG1
        
        has_address_param && stores_address
    }
    
    fn validates_module_code(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 100, self.bytecode.len());
        
        // Look for EXTCODESIZE or EXTCODEHASH checks
        self.bytecode[location..end]
            .iter()
            .any(|&b| b == 0x3b || b == 0x3f) // EXTCODESIZE or EXTCODEHASH
    }
    
    fn verifies_module_interface(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 100, self.bytecode.len());
        
        // Look for ERC-165 supportsInterface check
        // Pattern: STATICCALL with selector 0x01ffc9a7
        self.bytecode[location..end]
            .windows(5)
            .any(|w| {
                w[0] == 0x63 && // PUSH4
                w[1] == 0x01 && w[2] == 0xff && w[3] == 0xc9 && w[4] == 0xa7 // supportsInterface
            })
    }
    
    fn is_module_delegation(&self, location: usize) -> bool {
        // Check if DELEGATECALL target comes from module storage
        let start = location.saturating_sub(30);
        
        self.bytecode[start..location]
            .iter()
            .any(|&b| b == 0x54) // SLOAD (loading module address)
    }
    
    fn has_permission_boundaries(&self, location: usize) -> bool {
        let start = location.saturating_sub(40);
        
        // Look for permission checks before DELEGATECALL
        self.bytecode[start..location]
            .windows(5)
            .any(|w| {
                // SLOAD (permission), AND (masking), ISZERO, JUMPI
                w[0] == 0x54 && w[1] == 0x16 && w[2] == 0x15 && w[3] == 0x57
            })
    }
    
    fn is_hook_execution(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 70, self.bytecode.len());
        let section = &self.bytecode[location..end];
        
        // Hook execution: CALL/STATICCALL to module with specific pattern
        let has_call = section.iter().any(|&b| b == 0xf1 || b == 0xfa);
        let loads_from_storage = section.iter().any(|&b| b == 0x54);
        
        has_call && loads_from_storage
    }
    
    fn handles_hook_conflicts(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 70, self.bytecode.len());
        
        // Look for multiple hook checks or priority system
        let hook_checks = self.bytecode[location..end]
            .windows(3)
            .filter(|w| w[0] == 0x54 && w[1] == 0x15 && w[2] == 0x57) // SLOAD, ISZERO, JUMPI
            .count();
        
        hook_checks >= 2 // Multiple checks suggest conflict handling
    }
    
    fn has_hook_gas_limit(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 70, self.bytecode.len());
        
        // Look for GAS opcode and comparison before CALL
        self.bytecode[location..end]
            .windows(4)
            .any(|w| {
                w[0] == 0x5a && // GAS
                (w[1] == 0x10 || w[1] == 0x11) // LT or GT
            })
    }
    
    fn is_module_uninstall_function(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 90, self.bytecode.len());
        let section = &self.bytecode[location..end];
        
        // Uninstall typically: SLOAD, DELETE (SSTORE with 0)
        let has_sload = section.iter().any(|&b| b == 0x54);
        let has_delete = section.windows(3).any(|w| {
            w[0] == 0x60 && w[1] == 0x00 && w[2] == 0x55 // PUSH1 0, SSTORE
        });
        
        has_sload && has_delete
    }
    
    fn properly_cleans_module_state(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 90, self.bytecode.len());
        
        // Should have multiple SSTORE operations (cleaning various state)
        let sstore_count = self.bytecode[location..end]
            .iter()
            .filter(|&&b| b == 0x55)
            .count();
        
        sstore_count >= 3 // At least 3 storage cleanups
    }
    
    fn is_validation_function(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 100, self.bytecode.len());
        let section = &self.bytecode[location..end];
        
        // Validation function: checks signature, nonce, etc.
        let has_sig_check = section.iter().any(|&b| b == 0x01); // ECRECOVER precompile
        let has_comparisons = section.iter().filter(|&&b| b == 0x14).count() >= 2; // Multiple EQ
        
        has_sig_check || has_comparisons
    }
    
    fn validation_can_be_bypassed(&self, location: usize) -> bool {
        let end = std::cmp::min(location + 100, self.bytecode.len());
        
        // Look for validation that doesn't always execute
        // Pattern: validation check with no REVERT on failure
        let has_checks = self.bytecode[location..end]
            .iter()
            .any(|&b| b == 0x14); // EQ
        
        let has_revert = self.bytecode[location..end]
            .iter()
            .any(|&b| b == 0xfd); // REVERT
        
        has_checks && !has_revert
    }
    
    fn uses_isolated_storage(&self, location: usize) -> bool {
        let start = location.saturating_sub(10);
        
        // Check if storage slot is calculated/namespaced
        // Pattern: KECCAK256 for namespacing or large constant offset
        self.bytecode[start..location]
            .iter()
            .any(|&b| {
                b == 0x20 || // KECCAK256
                b == 0x69 || b == 0x6a // PUSH10/PUSH11 (large offset)
            })
    }
    
    fn is_in_module_context(&self, location: usize) -> bool {
        let start = location.saturating_sub(50);
        
        // Check if we're in a DELEGATECALL or module function
        self.bytecode[start..location]
            .iter()
            .any(|&b| b == 0xf4) // DELEGATECALL
    }
}
