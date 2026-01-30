use serde::{Deserialize, Serialize};

/// Double/Re-Initialization Attack Detection
/// 
/// Detects vulnerabilities allowing double initialization:
/// 1. Missing initialized flag check
/// 2. Initialize function callable multiple times
/// 3. Initialization in constructor + initialize()
/// 4. Delegate call initialization bypass
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DoubleInitializationAttackVulnerability {
    /// Critical: Initialize can be called multiple times
    ReinitializationPossible {
        description: String,
        initialize_location: usize,
        has_initialized_check: bool,
        confidence: f32,
    },
    /// High: Weak initialized flag
    WeakInitializedFlag {
        description: String,
        location: usize,
        flag_type: String,
    },
    /// Critical: Initialization via delegatecall bypass
    DelegatecallInitializationBypass {
        description: String,
        location: usize,
    },
    /// High: Constructor + initializer pattern
    ConstructorAndInitializer {
        description: String,
        constructor_loc: usize,
        initializer_loc: usize,
    },
}

pub struct DoubleInitializationAttackDetector {
    bytecode: Vec<u8>,
}

impl DoubleInitializationAttackDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<DoubleInitializationAttackVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Find initialize functions and check for re-initialization protection
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.is_initialize_function(i) {
                let initialized_check = self.has_proper_initialized_check(i, i + 150);
                let flag_strength = self.analyze_initialized_flag_strength(i, i + 150);
                
                if !initialized_check.0 {
                    vulnerabilities.push(DoubleInitializationAttackVulnerability::ReinitializationPossible {
                        description: "Initialize function can be called multiple times".to_string(),
                        initialize_location: i,
                        has_initialized_check: false,
                        confidence: 0.95,
                    });
                } else if flag_strength != "strong" {
                    vulnerabilities.push(DoubleInitializationAttackVulnerability::WeakInitializedFlag {
                        description: format!("Initialize has {} protection", flag_strength),
                        location: i,
                        flag_type: flag_strength,
                    });
                }
            }
        }
        
        // Pattern 2: Delegatecall initialization bypass
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.has_delegatecall_pattern(i) {
                let can_bypass_init_check = self.delegatecall_bypasses_initialization(i, i + 100);
                
                if can_bypass_init_check {
                    vulnerabilities.push(DoubleInitializationAttackVulnerability::DelegatecallInitializationBypass {
                        description: "Delegatecall can bypass initialization checks".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 3: Both constructor and initializer present
        let has_constructor = self.has_constructor_logic();
        let initializers = self.find_all_initializers();
        
        if has_constructor && !initializers.is_empty() {
            for init_loc in initializers {
                vulnerabilities.push(DoubleInitializationAttackVulnerability::ConstructorAndInitializer {
                    description: "Contract has both constructor and initialize() - potential confusion".to_string(),
                    constructor_loc: 0,
                    initializer_loc: init_loc,
                });
            }
        }
        
        vulnerabilities
    }
    
    fn is_initialize_function(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // Common initialize selectors:
        // initialize(): 0x8129fc1c
        // init(): 0xe1c7392a
        // __init__(): various
        
        self.bytecode[location..location + 30].windows(4).any(|w| {
            w[0] == 0x63 && (
                (w[1] == 0x81 && w[2] == 0x29 && w[3] == 0xfc) || // initialize
                (w[1] == 0xe1 && w[2] == 0xc7 && w[3] == 0x39) || // init
                (w[1] == 0xf0 && w[2] == 0x9a && w[3] == 0x48)    // setUp (test pattern)
            )
        })
    }
    
    fn has_proper_initialized_check(&self, start: usize, end: usize) -> (bool, Option<usize>) {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return (false, None);
        }
        
        // Proper initialization check pattern:
        // 1. SLOAD from initialized slot
        // 2. Check if already initialized (ISZERO or direct check)
        // 3. REVERT if already initialized
        // 4. SSTORE to set initialized = true
        
        let mut found_sload = None;
        let mut found_check = false;
        let mut found_revert = false;
        let mut found_sstore = false;
        
        for i in start..range_end {
            if self.bytecode[i] == 0x54 && found_sload.is_none() { // First SLOAD
                found_sload = Some(i);
            }
            
            if self.bytecode[i] == 0x15 || self.bytecode[i] == 0x14 { // ISZERO or EQ
                found_check = true;
            }
            
            if self.bytecode[i] == 0xfd { // REVERT
                found_revert = true;
            }
            
            if self.bytecode[i] == 0x55 && found_sload.is_some() { // SSTORE after SLOAD
                found_sstore = true;
            }
        }
        
        let has_full_pattern = found_sload.is_some() && found_check && found_revert && found_sstore;
        (has_full_pattern, found_sload)
    }
    
    fn analyze_initialized_flag_strength(&self, start: usize, end: usize) -> String {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return "none".to_string();
        }
        
        // Strong: Uses Initializable pattern with version number
        // Medium: Boolean flag with proper checks
        // Weak: Simple check without revert
        // None: No check
        
        let (has_check, _) = self.has_proper_initialized_check(start, end);
        
        if !has_check {
            return "none".to_string();
        }
        
        // Check if uses version number (Initializable pattern)
        let has_version_number = self.bytecode[start..range_end]
            .windows(3)
            .any(|w| {
                w[0] == 0x60 && w[1] > 0 && w[1] < 10 && // PUSH1 with small number (version)
                w[2] == 0x10 // LT (version check)
            });
        
        if has_version_number {
            return "strong".to_string();
        }
        
        // Check if has revert
        let has_revert = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0xfd);
        
        if has_revert {
            return "medium".to_string();
        }
        
        "weak".to_string()
    }
    
    fn has_delegatecall_pattern(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        self.bytecode[location..location + 20]
            .iter()
            .any(|&b| b == 0xf4) // DELEGATECALL
    }
    
    fn delegatecall_bypasses_initialization(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // If delegatecall is used AND there's state modification
        // without checking initialized flag, it can bypass
        
        let has_delegatecall = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0xf4);
        
        let has_state_modification = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x55); // SSTORE
        
        let checks_initialized = self.bytecode[start..range_end]
            .windows(5)
            .any(|w| {
                w.iter().any(|&b| b == 0x54) && // SLOAD
                w.iter().any(|&b| b == 0x15)    // ISZERO
            });
        
        has_delegatecall && has_state_modification && !checks_initialized
    }
    
    fn has_constructor_logic(&self) -> bool {
        // Constructor is executed at deployment
        // Look for CODECOPY pattern (copies runtime code)
        
        self.bytecode.windows(3).any(|w| {
            w[0] == 0x39 && // CODECOPY
            w[1] == 0xf3    // RETURN (end of constructor)
        })
    }
    
    fn find_all_initializers(&self) -> Vec<usize> {
        let mut initializers = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(30) {
            if self.is_initialize_function(i) {
                initializers.push(i);
            }
        }
        
        initializers
    }
}
