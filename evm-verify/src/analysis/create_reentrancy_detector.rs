use serde::{Deserialize, Serialize};

/// CREATE/CREATE2 Reentrancy Detection
/// 
/// Detects reentrancy through constructor callbacks:
/// 1. Constructor calls back to deployer before completion
/// 2. CREATE2 with predictable address + reentrancy
/// 3. Factory pattern reentrancy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CreateReentrancyVulnerability {
    /// Critical: Constructor callback reentrancy
    ConstructorCallbackReentrancy {
        description: String,
        create_location: usize,
        callback_detected: bool,
        confidence: f32,
    },
    /// High: CREATE2 address prediction exploit
    Create2AddressPredictionAttack {
        description: String,
        create2_location: usize,
        salt_controllable: bool,
    },
    /// High: Factory reentrancy during deployment
    FactoryReentrancy {
        description: String,
        factory_location: usize,
        state_modified_before_create: bool,
    },
}

pub struct CreateReentrancyDetector {
    bytecode: Vec<u8>,
}

impl CreateReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CreateReentrancyVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: CREATE with constructor callback
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.bytecode[i] == 0xf0 { // CREATE
                // Check if code being deployed might callback
                let constructor_code = self.extract_constructor_code(i);
                let has_callback = self.has_callback_in_constructor(&constructor_code);
                
                // Check if state is read after CREATE (vulnerable to reentrancy)
                let state_read_after = self.has_storage_read_after(i, i + 100);
                
                if has_callback && state_read_after {
                    vulnerabilities.push(CreateReentrancyVulnerability::ConstructorCallbackReentrancy {
                        description: "Constructor can callback before completion, state read afterwards".to_string(),
                        create_location: i,
                        callback_detected: true,
                        confidence: 0.85,
                    });
                }
            }
        }
        
        // Pattern 2: CREATE2 with controllable salt
        for i in 0..self.bytecode.len().saturating_sub(120) {
            if self.bytecode[i] == 0xf5 { // CREATE2
                let salt_controllable = self.is_salt_user_controlled(i);
                let address_used_before_deploy = self.address_used_in_logic_before(i);
                
                if salt_controllable && address_used_before_deploy {
                    vulnerabilities.push(CreateReentrancyVulnerability::Create2AddressPredictionAttack {
                        description: "CREATE2 with user-controlled salt, address used before deployment".to_string(),
                        create2_location: i,
                        salt_controllable: true,
                    });
                }
            }
        }
        
        // Pattern 3: Factory pattern state modification before CREATE
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.bytecode[i] == 0xf0 || self.bytecode[i] == 0xf5 { // CREATE or CREATE2
                // Check if critical state is modified BEFORE the CREATE
                let state_mod_before = self.has_state_modification_before(i);
                let is_factory_pattern = self.is_factory_pattern(i);
                
                if state_mod_before && is_factory_pattern {
                    vulnerabilities.push(CreateReentrancyVulnerability::FactoryReentrancy {
                        description: "Factory modifies state before CREATE, vulnerable to constructor reentrancy".to_string(),
                        factory_location: i,
                        state_modified_before_create: true,
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn extract_constructor_code(&self, create_loc: usize) -> Vec<u8> {
        // Constructor code is pushed onto stack before CREATE
        // Look backwards for large PUSH operations
        let search_start = create_loc.saturating_sub(500);
        let mut constructor_code = Vec::new();
        
        for i in search_start..create_loc {
            if self.bytecode[i] >= 0x60 && self.bytecode[i] <= 0x7f { // PUSH1-PUSH32
                let push_size = (self.bytecode[i] - 0x5f) as usize;
                if push_size > 10 && i + push_size < self.bytecode.len() {
                    // This might be constructor code
                    constructor_code = self.bytecode[i+1..i+1+push_size].to_vec();
                }
            }
        }
        
        constructor_code
    }
    
    fn has_callback_in_constructor(&self, constructor_code: &[u8]) -> bool {
        if constructor_code.is_empty() {
            return false;
        }
        
        // Check for CALL/DELEGATECALL in constructor
        constructor_code.iter().any(|&b| b == 0xf1 || b == 0xf4)
    }
    
    fn has_storage_read_after(&self, create_loc: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        // Check if SLOAD happens after CREATE
        self.bytecode[create_loc..range_end]
            .iter()
            .any(|&b| b == 0x54) // SLOAD
    }
    
    fn is_salt_user_controlled(&self, create2_loc: usize) -> bool {
        // Look backwards for salt source - if it comes from CALLDATALOAD, it's user-controlled
        let search_start = create2_loc.saturating_sub(50);
        
        self.bytecode[search_start..create2_loc]
            .iter()
            .any(|&b| b == 0x35) // CALLDATALOAD
    }
    
    fn address_used_in_logic_before(&self, create2_loc: usize) -> bool {
        // Check if computed address is used in logic before actual deployment
        let search_start = create2_loc.saturating_sub(100);
        
        // Look for address computation (keccak256) followed by storage write
        let has_address_calc = self.bytecode[search_start..create2_loc]
            .iter()
            .any(|&b| b == 0x20); // SHA3
        
        let has_storage_write = self.bytecode[search_start..create2_loc]
            .iter()
            .any(|&b| b == 0x55); // SSTORE
        
        has_address_calc && has_storage_write
    }
    
    fn has_state_modification_before(&self, create_loc: usize) -> bool {
        // Check for SSTORE operations before CREATE
        let search_start = create_loc.saturating_sub(100);
        
        for i in search_start..create_loc {
            if self.bytecode[i] == 0x55 { // SSTORE
                // Check it's not just temporary state
                if i > 5 && self.bytecode[i-2] == 0x60 { // PUSH1 (slot)
                    let slot = self.bytecode[i-1];
                    if slot < 20 { // Low slots are likely persistent state
                        return true;
                    }
                }
            }
        }
        
        false
    }
    
    fn is_factory_pattern(&self, create_loc: usize) -> bool {
        // Factory patterns typically:
        // 1. Take constructor parameters from calldata
        // 2. Store deployed address
        // 3. Emit event
        
        let search_range = create_loc.saturating_sub(50)..create_loc.saturating_add(50).min(self.bytecode.len());
        
        let has_calldata = self.bytecode[search_range.clone()]
            .iter()
            .any(|&b| b == 0x35); // CALLDATALOAD
        
        let has_log = self.bytecode[search_range.clone()]
            .iter()
            .any(|&b| b >= 0xa0 && b <= 0xa4); // LOG0-LOG4
        
        let has_address_storage = self.bytecode[search_range]
            .windows(2)
            .any(|w| w[0] == 0x55 && w[1] == 0x30); // SSTORE + ADDRESS
        
        has_calldata && (has_log || has_address_storage)
    }
}
