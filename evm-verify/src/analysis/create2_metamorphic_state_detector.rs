use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// CREATE2 Metamorphic Contract State Manipulation Detection
/// 
/// Detects vulnerabilities from CREATE2 metamorphic contracts:
/// 1. Contract can be destroyed and redeployed with different code
/// 2. State persistence across metamorphosis
/// 3. Address prediction exploits
/// 4. SELFDESTRUCT + CREATE2 redeployment pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Create2MetamorphicStateVulnerability {
    /// Critical: Metamorphic contract pattern detected
    MetamorphicContractPattern {
        description: String,
        create2_location: usize,
        selfdestruct_location: Option<usize>,
        confidence: f32,
    },
    /// High: State persists across metamorphosis
    StatePersistenceAcrossRedeploy {
        description: String,
        location: usize,
        affected_slots: Vec<u8>,
    },
    /// Critical: Address used before deployment verification
    AddressUsedBeforeDeploymentCheck {
        description: String,
        location: usize,
    },
    /// High: Bytecode hash not verified
    BytecodeHashNotVerified {
        description: String,
        location: usize,
    },
}

pub struct Create2MetamorphicStateDetector {
    bytecode: Vec<u8>,
}

impl Create2MetamorphicStateDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<Create2MetamorphicStateVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Pattern 1: Detect metamorphic pattern (CREATE2 + SELFDESTRUCT)
        let create2_locations = self.find_create2_operations();
        let selfdestruct_locations = self.find_selfdestruct_operations();
        
        for create2_loc in &create2_locations {
            if !selfdestruct_locations.is_empty() {
                // This contract can deploy contracts that can selfdestruct
                let salt_controllable = self.is_salt_controllable(*create2_loc);
                
                if salt_controllable {
                    vulnerabilities.push(Create2MetamorphicStateVulnerability::MetamorphicContractPattern {
                        description: "Metamorphic contract pattern: CREATE2 with controllable salt + SELFDESTRUCT".to_string(),
                        create2_location: *create2_loc,
                        selfdestruct_location: selfdestruct_locations.first().copied(),
                        confidence: 0.90,
                    });
                }
            }
        }
        
        // Pattern 2: State read after CREATE2
        for create2_loc in &create2_locations {
            let state_slots = self.find_state_reads_after_create2(*create2_loc, create2_loc + 200);
            
            if !state_slots.is_empty() {
                let address_from_create2 = self.get_deployed_address_location(*create2_loc);
                
                if address_from_create2.is_some() {
                    vulnerabilities.push(Create2MetamorphicStateVulnerability::StatePersistenceAcrossRedeploy {
                        description: "State read from CREATE2 deployed contract - vulnerable if redeployed".to_string(),
                        location: *create2_loc,
                        affected_slots: state_slots,
                    });
                }
            }
        }
        
        // Pattern 3: Address used before extcodesize check
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.is_address_calculation(i) {
                let address_used_before_check = self.address_used_without_code_check(i, i + 150);
                
                if address_used_before_check {
                    vulnerabilities.push(Create2MetamorphicStateVulnerability::AddressUsedBeforeDeploymentCheck {
                        description: "CREATE2 address used in logic before verifying code exists".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 4: Bytecode hash verification
        for create2_loc in &create2_locations {
            let verifies_bytecode_hash = self.verifies_deployed_bytecode_hash(*create2_loc, create2_loc + 150);
            
            if !verifies_bytecode_hash {
                vulnerabilities.push(Create2MetamorphicStateVulnerability::BytecodeHashNotVerified {
                    description: "CREATE2 deployed contract bytecode hash not verified".to_string(),
                    location: *create2_loc,
                });
            }
        }
        
        vulnerabilities
    }
    
    fn find_create2_operations(&self) -> Vec<usize> {
        let mut locations = Vec::new();
        
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xf5 { // CREATE2
                locations.push(i);
            }
        }
        
        locations
    }
    
    fn find_selfdestruct_operations(&self) -> Vec<usize> {
        let mut locations = Vec::new();
        
        for i in 0..self.bytecode.len() {
            if self.bytecode[i] == 0xff { // SELFDESTRUCT
                locations.push(i);
            }
        }
        
        locations
    }
    
    fn is_salt_controllable(&self, create2_location: usize) -> bool {
        // Look backwards for salt source
        let search_start = create2_location.saturating_sub(100);
        
        // Salt is controllable if it comes from:
        // 1. CALLDATALOAD (user input)
        // 2. CALLER (user address)
        // 3. Storage that can be modified by users
        
        let uses_calldata = self.bytecode[search_start..create2_location]
            .iter()
            .any(|&b| b == 0x35); // CALLDATALOAD
        
        let uses_caller = self.bytecode[search_start..create2_location]
            .iter()
            .any(|&b| b == 0x33); // CALLER
        
        uses_calldata || uses_caller
    }
    
    fn find_state_reads_after_create2(&self, create2_loc: usize, end: usize) -> Vec<u8> {
        let range_end = end.min(self.bytecode.len());
        let mut slots = HashSet::new();
        
        // Find STATICCALL or CALL to the deployed address with subsequent state reads
        let mut found_call_to_deployed = false;
        
        for i in create2_loc..range_end {
            // CREATE2 pushes address on stack
            if self.bytecode[i] == 0xfa || self.bytecode[i] == 0xf1 { // STATICCALL or CALL
                found_call_to_deployed = true;
            }
            
            if found_call_to_deployed {
                // Look for state reads (SLOAD with specific pattern)
                if self.bytecode[i] == 0x54 { // SLOAD
                    if let Some(slot) = self.get_slot_number(i) {
                        slots.insert(slot);
                    }
                }
            }
        }
        
        slots.into_iter().collect()
    }
    
    fn get_slot_number(&self, sload_location: usize) -> Option<u8> {
        // Look backwards for PUSH1 that specifies slot
        for i in (sload_location.saturating_sub(10)..sload_location).rev() {
            if self.bytecode[i] == 0x60 && i + 1 < self.bytecode.len() { // PUSH1
                return Some(self.bytecode[i + 1]);
            }
        }
        None
    }
    
    fn get_deployed_address_location(&self, create2_location: usize) -> Option<usize> {
        // CREATE2 pushes deployed address on stack
        // Look for DUP or SWAP operations that save the address
        let search_end = (create2_location + 20).min(self.bytecode.len());
        
        for i in create2_location..search_end {
            if self.bytecode[i] >= 0x80 && self.bytecode[i] <= 0x8f { // DUP1-DUP16
                return Some(i);
            }
        }
        
        None
    }
    
    fn is_address_calculation(&self, location: usize) -> bool {
        if location + 40 > self.bytecode.len() {
            return false;
        }
        
        // CREATE2 address calculation:
        // keccak256(0xff ++ address ++ salt ++ keccak256(init_code))
        
        self.bytecode[location..location + 40].windows(5).any(|w| {
            w.iter().any(|&b| b == 0x20) && // SHA3/KECCAK256
            w.iter().any(|&b| b == 0x60 && w[1] == 0xff) // PUSH1 0xff
        })
    }
    
    fn address_used_without_code_check(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // Address is used if there's a CALL/STATICCALL to it
        let has_call = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0xf1 || b == 0xfa); // CALL or STATICCALL
        
        // Code check uses EXTCODESIZE
        let has_code_check = self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0x3b); // EXTCODESIZE
        
        has_call && !has_code_check
    }
    
    fn verifies_deployed_bytecode_hash(&self, create2_loc: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if create2_loc >= range_end {
            return false;
        }
        
        // Bytecode hash verification pattern:
        // 1. EXTCODEHASH of deployed address
        // 2. Compare with expected hash
        // 3. REVERT if mismatch
        
        let has_extcodehash = self.bytecode[create2_loc..range_end]
            .iter()
            .any(|&b| b == 0x3f); // EXTCODEHASH
        
        let has_comparison = self.bytecode[create2_loc..range_end]
            .iter()
            .any(|&b| b == 0x14); // EQ
        
        let has_revert = self.bytecode[create2_loc..range_end]
            .iter()
            .any(|&b| b == 0xfd); // REVERT
        
        has_extcodehash && has_comparison && has_revert
    }
}
