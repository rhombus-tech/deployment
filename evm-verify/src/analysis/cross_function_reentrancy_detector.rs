use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Cross-Function Reentrancy Detection
/// 
/// Detects reentrancy attacks across different functions:
/// 1. Function A calls external -> Function B modifies state
/// 2. Shared state modifications without proper locking
/// 3. Cross-contract reentrancy patterns
/// 4. Read-after-write hazards across functions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CrossFunctionReentrancyVulnerability {
    /// Critical: Cross-function state manipulation
    CrossFunctionStateRace {
        description: String,
        function_a: usize,
        function_b: usize,
        shared_slot: u8,
        confidence: f32,
    },
    /// High: External call without cross-function lock
    MissingCrossFunctionLock {
        description: String,
        location: usize,
        vulnerable_functions: Vec<String>,
    },
    /// Critical: Callback reenters different function
    CallbackReentrancyAcrossFunctions {
        description: String,
        callback_location: usize,
        target_function: usize,
    },
    /// High: Read-after-write hazard across functions
    ReadAfterWriteHazard {
        description: String,
        reader_function: usize,
        writer_function: usize,
        storage_slot: u8,
    },
}

pub struct CrossFunctionReentrancyDetector {
    bytecode: Vec<u8>,
}

impl CrossFunctionReentrancyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CrossFunctionReentrancyVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Build comprehensive function map
        let functions = self.identify_functions();
        let function_calls = self.map_function_calls(&functions);
        
        // Pattern 1: Cross-function state races
        for (&func_a_loc, func_a_data) in &functions {
            for (&func_b_loc, func_b_data) in &functions {
                if func_a_loc != func_b_loc {
                    // Find shared storage slots
                    let shared: Vec<_> = func_a_data.storage_writes
                        .intersection(&func_b_data.storage_writes)
                        .collect();
                    
                    for &&slot in &shared {
                        // Check if func_a has external call before state write
                        let a_has_ext_call = func_a_data.has_external_call;
                        let a_writes_after_call = self.writes_after_external_call(func_a_loc, slot);
                        
                        // Check if func_b can be called and modifies same slot
                        let b_is_public = func_b_data.is_public;
                        
                        if a_has_ext_call && !a_writes_after_call && b_is_public {
                            vulnerabilities.push(CrossFunctionReentrancyVulnerability::CrossFunctionStateRace {
                                description: format!(
                                    "Function {} calls external before write, function {} can reenter and modify shared slot {}",
                                    func_a_loc, func_b_loc, slot
                                ),
                                function_a: func_a_loc,
                                function_b: func_b_loc,
                                shared_slot: slot,
                                confidence: 0.90,
                            });
                        }
                    }
                }
            }
        }
        
        // Pattern 2: Functions with external calls but no reentrancy guard
        for (&location, func_data) in &functions {
            if func_data.has_external_call {
                let has_guard = self.has_reentrancy_guard_advanced(location);
                
                if !has_guard {
                    // Find which other public functions share storage
                    let vulnerable_funcs = self.find_vulnerable_peer_functions_real(
                        location,
                        &func_data.storage_writes,
                        &functions
                    );
                    
                    if !vulnerable_funcs.is_empty() {
                        vulnerabilities.push(CrossFunctionReentrancyVulnerability::MissingCrossFunctionLock {
                            description: format!(
                                "External call without reentrancy guard, {} peer functions share storage",
                                vulnerable_funcs.len()
                            ),
                            location,
                            vulnerable_functions: vulnerable_funcs,
                        });
                    }
                }
            }
        }
        
        // Pattern 3: Callback patterns with cross-function targets
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if let Some(callback_sig) = self.detect_callback_pattern(i) {
                // Find the target function that will be called
                let targets = self.find_callback_targets_real(i, &callback_sig, &functions);
                
                for target in targets {
                    if target != i && target > 0 {
                        vulnerabilities.push(CrossFunctionReentrancyVulnerability::CallbackReentrancyAcrossFunctions {
                            description: format!(
                                "Callback {} can reenter function at {}",
                                callback_sig, target
                            ),
                            callback_location: i,
                            target_function: target,
                        });
                    }
                }
            }
        }
        
        // Pattern 4: Read-after-write hazards
        for (&reader_loc, reader_data) in &functions {
            if reader_data.has_external_call {
                for (&writer_loc, writer_data) in &functions {
                    if reader_loc != writer_loc && writer_data.is_public {
                        // Find slots that reader reads before external call
                        // and writer modifies
                        let hazards: Vec<_> = reader_data.storage_reads
                            .intersection(&writer_data.storage_writes)
                            .collect();
                        
                        for &&slot in &hazards {
                            if self.reads_before_external_call(reader_loc, slot) {
                                vulnerabilities.push(CrossFunctionReentrancyVulnerability::ReadAfterWriteHazard {
                                    description: format!(
                                        "Function {} reads slot {} before external call, function {} can reenter and modify it",
                                        reader_loc, slot, writer_loc
                                    ),
                                    reader_function: reader_loc,
                                    writer_function: writer_loc,
                                    storage_slot: slot,
                                });
                            }
                        }
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn identify_functions(&self) -> HashMap<usize, FunctionData> {
        let mut functions = HashMap::new();
        
        // Find function entry points using JUMPDEST after function dispatch
        let mut i = 0;
        while i < self.bytecode.len() {
            if self.bytecode[i] == 0x5b { // JUMPDEST
                // Check if this looks like a function entry (after EQ + JUMPI pattern)
                let is_function_entry = i > 10 && self.is_after_function_selector(i);
                
                if is_function_entry {
                    let func_data = self.analyze_function(i);
                    functions.insert(i, func_data);
                }
            }
            i += 1;
        }
        
        functions
    }
    
    fn is_after_function_selector(&self, jumpdest_loc: usize) -> bool {
        // Look backwards for function selector pattern: PUSH4 + EQ + JUMPI
        let search_start = jumpdest_loc.saturating_sub(20);
        
        for i in search_start..jumpdest_loc {
            if i + 4 < self.bytecode.len() {
                if self.bytecode[i] == 0x63 && // PUSH4
                   self.bytecode[i + 5] == 0x14 && // EQ
                   self.bytecode[i + 6] == 0x57 { // JUMPI
                    return true;
                }
            }
        }
        false
    }
    
    fn analyze_function(&self, start: usize) -> FunctionData {
        let end = self.find_function_end(start);
        
        let storage_reads = self.extract_storage_reads(start, end);
        let storage_writes = self.extract_storage_writes(start, end);
        let has_external_call = self.has_external_call_in_range(start, end);
        let is_public = true; // If it has function selector, it's public
        let external_call_location = self.find_external_call_location(start, end);
        
        FunctionData {
            start,
            end,
            storage_reads,
            storage_writes,
            has_external_call,
            is_public,
            external_call_location,
        }
    }
    
    fn find_function_end(&self, start: usize) -> usize {
        // Find next JUMPDEST or STOP/RETURN/REVERT
        for i in start..self.bytecode.len() {
            if self.bytecode[i] == 0x5b && i != start { // Next JUMPDEST
                return i;
            }
            if self.bytecode[i] == 0x00 || // STOP
               self.bytecode[i] == 0xf3 || // RETURN
               self.bytecode[i] == 0xfd {  // REVERT
                return i + 1;
            }
        }
        (start + 500).min(self.bytecode.len())
    }
    
    fn extract_storage_reads(&self, start: usize, end: usize) -> HashSet<u8> {
        let mut slots = HashSet::new();
        
        for i in start..end {
            if self.bytecode[i] == 0x54 { // SLOAD
                if let Some(slot) = self.get_storage_slot_before(i) {
                    slots.insert(slot);
                }
            }
        }
        
        slots
    }
    
    fn extract_storage_writes(&self, start: usize, end: usize) -> HashSet<u8> {
        let mut slots = HashSet::new();
        
        for i in start..end {
            if self.bytecode[i] == 0x55 { // SSTORE
                if let Some(slot) = self.get_storage_slot_before(i) {
                    slots.insert(slot);
                }
            }
        }
        
        slots
    }
    
    fn get_storage_slot_before(&self, sload_or_sstore_loc: usize) -> Option<u8> {
        // Look backwards for PUSH1 that puts slot on stack
        for i in (sload_or_sstore_loc.saturating_sub(10)..sload_or_sstore_loc).rev() {
            if self.bytecode[i] == 0x60 && i + 1 < self.bytecode.len() { // PUSH1
                return Some(self.bytecode[i + 1]);
            }
        }
        None
    }
    
    fn has_external_call_in_range(&self, start: usize, end: usize) -> bool {
        for i in start..end {
            if self.bytecode[i] == 0xf1 || // CALL
               self.bytecode[i] == 0xf4 || // DELEGATECALL
               self.bytecode[i] == 0xfa {  // STATICCALL
                return true;
            }
        }
        false
    }
    
    fn find_external_call_location(&self, start: usize, end: usize) -> Option<usize> {
        for i in start..end {
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xf4 || self.bytecode[i] == 0xfa {
                return Some(i);
            }
        }
        None
    }
    
    fn writes_after_external_call(&self, func_start: usize, slot: u8) -> bool {
        let func_end = self.find_function_end(func_start);
        
        // Find external call location
        if let Some(call_loc) = self.find_external_call_location(func_start, func_end) {
            // Check if SSTORE to this slot happens after the call
            for i in call_loc..func_end {
                if self.bytecode[i] == 0x55 { // SSTORE
                    if let Some(written_slot) = self.get_storage_slot_before(i) {
                        if written_slot == slot {
                            return true;
                        }
                    }
                }
            }
        }
        
        false
    }
    
    fn reads_before_external_call(&self, func_start: usize, slot: u8) -> bool {
        let func_end = self.find_function_end(func_start);
        
        if let Some(call_loc) = self.find_external_call_location(func_start, func_end) {
            // Check if SLOAD from this slot happens before the call
            for i in func_start..call_loc {
                if self.bytecode[i] == 0x54 { // SLOAD
                    if let Some(read_slot) = self.get_storage_slot_before(i) {
                        if read_slot == slot {
                            return true;
                        }
                    }
                }
            }
        }
        
        false
    }
    
    fn has_reentrancy_guard_advanced(&self, func_start: usize) -> bool {
        let func_end = self.find_function_end(func_start);
        
        // Look for nonReentrant pattern:
        // 1. SLOAD from lock slot
        // 2. Check it's not locked
        // 3. SSTORE to set lock
        // 4. ... function body ...
        // 5. SSTORE to clear lock
        
        let mut lock_slot = None;
        let mut first_sstore = None;
        let mut last_sstore = None;
        
        for i in func_start..func_end {
            if self.bytecode[i] == 0x55 { // SSTORE
                if let Some(slot) = self.get_storage_slot_before(i) {
                    if first_sstore.is_none() {
                        first_sstore = Some((i, slot));
                        lock_slot = Some(slot);
                    } else if Some(slot) == lock_slot {
                        last_sstore = Some((i, slot));
                    }
                }
            }
        }
        
        // Guard detected if same slot written at start and end
        first_sstore.is_some() && last_sstore.is_some() && 
        first_sstore.map(|(_, s)| s) == last_sstore.map(|(_, s)| s)
    }
    
    fn find_vulnerable_peer_functions_real(
        &self,
        _location: usize,
        storage_slots: &HashSet<u8>,
        functions: &HashMap<usize, FunctionData>
    ) -> Vec<String> {
        let mut vulnerable = Vec::new();
        
        for (loc, func_data) in functions {
            if func_data.is_public {
                // Check if this function shares storage with the caller
                let shares_storage = !func_data.storage_writes
                    .intersection(storage_slots)
                    .collect::<Vec<_>>()
                    .is_empty();
                
                if shares_storage {
                    vulnerable.push(format!("function_at_0x{:x}", loc));
                }
            }
        }
        
        vulnerable
    }
    
    fn detect_callback_pattern(&self, location: usize) -> Option<String> {
        if location + 30 > self.bytecode.len() {
            return None;
        }
        
        // Known callback selectors
        let callbacks = vec![
            (0x150b7a02, "onERC721Received"),
            (0xf23a6e61, "onERC1155Received"),
            (0xbc197c81, "onERC1155BatchReceived"),
            (0x0b0e4e62, "tokensReceived"),
        ];
        
        for (selector, name) in callbacks {
            if self.has_function_selector(location, selector) {
                return Some(name.to_string());
            }
        }
        
        None
    }
    
    fn has_function_selector(&self, location: usize, selector: u32) -> bool {
        if location + 4 > self.bytecode.len() {
            return false;
        }
        
        let bytes = selector.to_be_bytes();
        self.bytecode[location] == 0x63 && // PUSH4
        self.bytecode[location + 1] == bytes[0] &&
        self.bytecode[location + 2] == bytes[1] &&
        self.bytecode[location + 3] == bytes[2] &&
        self.bytecode[location + 4] == bytes[3]
    }
    
    fn find_callback_targets_real(
        &self,
        callback_loc: usize,
        _callback_sig: &str,
        functions: &HashMap<usize, FunctionData>
    ) -> Vec<usize> {
        let mut targets = Vec::new();
        
        // Find CALL instructions in callback that might reenter
        let callback_end = self.find_function_end(callback_loc);
        
        for i in callback_loc..callback_end {
            if self.bytecode[i] == 0xf1 { // CALL
                // The call could reenter any public function
                for (loc, func_data) in functions {
                    if func_data.is_public && *loc != callback_loc {
                        targets.push(*loc);
                    }
                }
                break;
            }
        }
        
        targets
    }
    
    fn map_function_calls(&self, _functions: &HashMap<usize, FunctionData>) -> HashMap<usize, Vec<usize>> {
        // Maps which functions call which other functions
        HashMap::new()
    }
}

#[derive(Debug, Clone)]
struct FunctionData {
    start: usize,
    end: usize,
    storage_reads: HashSet<u8>,
    storage_writes: HashSet<u8>,
    has_external_call: bool,
    is_public: bool,
    external_call_location: Option<usize>,
}
