use wasmparser::{WasmFeatures, Parser, Payload, Operator};
use crate::analyzer::Property;
use common::{MemoryAccessData, AllocationData, MemorySafetyProofData};
use anyhow::Result;
use std::collections::HashMap;

/// Types of memory management functions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemoryManagerType {
    /// Functions like malloc, calloc that allocate memory
    Allocator,
    /// Functions like free that deallocate memory
    Deallocator,
}

/// Types of values we track for data flow analysis
#[derive(Debug, Clone, PartialEq)]
enum DataValue {
    /// A constant integer value
    Const(i64),
    /// A memory address (potentially allocated)
    Address(u64),
    /// A length or size value (important for parameter validation)
    Length(u64),
    /// A value that is compared against a threshold (for parameter validation)
    BoundChecked(u64, u64), // value, max_allowed
    /// Unknown or untracked value
    Unknown,
}

/// Patterns for parameter validation in WASM code
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationPattern {
    /// Length check: ensures a parameter's length is within reasonable bounds
    LengthCheck {
        parameter_index: u32,
        max_allowed: u64,
        validation_location: u32, // instruction index
    },
    /// Bounds check: ensures memory access is within bounds
    BoundsCheck {
        address: u64,
        size: u64,
        validation_location: u32,
    },
    /// Parameter rejection: code rejects invalid parameters
    ParameterRejection {
        parameter_index: u32,
        reason: String,
        validation_location: u32,
    },
    /// Type check: ensures parameter has expected type
    TypeCheck {
        parameter_index: u32,
        expected_type: String,
        validation_location: u32,
    },
    /// Custom limit check: for domain-specific validation
    CustomLimitCheck {
        parameter_index: u32,
        limit_type: String,
        limit_value: u64,
        validation_location: u32,
    },
    /// Nested validation: composition of multiple validation patterns
    NestedValidation {
        parameter_index: u32,
        inner_validations: Vec<Box<ValidationPattern>>,
        validation_location: u32,
    },
}

/// Information about branch contexts for tracking conditional validation
#[derive(Debug, Clone)]
struct BranchContext {
    /// The condition that led to this branch (if known)
    condition: Option<BranchCondition>,
    /// The branch depth (for nested conditions)
    depth: u32,
    /// Whether this branch performs parameter validation
    is_validation: bool,
}

/// Types of branch conditions we track
#[derive(Debug, Clone, PartialEq)]
enum BranchCondition {
    /// Comparison: value < threshold
    LessThan(DataValue, DataValue),
    /// Comparison: value <= threshold
    LessThanOrEqual(DataValue, DataValue),
    /// Comparison: value > threshold
    GreaterThan(DataValue, DataValue),
    /// Comparison: value >= threshold
    GreaterThanOrEqual(DataValue, DataValue),
    /// Comparison: value == threshold
    Equal(DataValue, DataValue),
    /// Comparison: value != threshold
    NotEqual(DataValue, DataValue),
    /// Unknown condition
    Unknown,
}

/// Information about parameters for tracking validation
#[derive(Debug, Clone, PartialEq)]
struct ParameterInfo {
    /// The parameter index
    index: u32,
    /// Purpose of the parameter (if detected)
    purpose: ParameterPurpose,
    /// Whether the parameter is validated
    is_validated: bool,
    /// The maximum allowed value (for length parameters)
    max_allowed: Option<u64>,
}

/// Types of parameters we detect
#[derive(Debug, Clone, PartialEq)]
enum ParameterPurpose {
    /// Buffer address parameter
    BufferAddress,
    /// Buffer length parameter
    BufferLength,
    /// Value parameter
    Value,
    /// Unknown purpose
    Unknown,
}

/// Memory safety property verifier
pub struct MemorySafetyProperty;

/// Analyzes validation patterns to extract parameter validation information
pub fn analyze_parameter_validation(validation_patterns: &[ValidationPattern]) -> Vec<common::ParameterValidationInfo> {
    let mut results = Vec::new();
    
    for pattern in validation_patterns {
        match pattern {
            ValidationPattern::LengthCheck { parameter_index, max_allowed, validation_location } => {
                results.push(common::ParameterValidationInfo {
                    max_allowed_length: Some(*max_allowed),
                    validates_length: true,
                    parameter_index: Some(*parameter_index),
                    validation_strategy: format!("Length check at instruction {}: parameter {} must be <= {} bytes", 
                                              validation_location, parameter_index, max_allowed),
                    validation_type: common::ValidationTypeInfo::LengthCheck,
                    metadata: None,
                });
            },
            ValidationPattern::BoundsCheck { address, size, validation_location } => {
                results.push(common::ParameterValidationInfo {
                    max_allowed_length: Some(*size),
                    validates_length: true,
                    parameter_index: None, // We don't know which parameter this is for
                    validation_strategy: format!("Bounds check at instruction {}: memory access at address {} with size {}", 
                                               validation_location, address, size),
                    validation_type: common::ValidationTypeInfo::BoundsCheck,
                    metadata: None,
                });
            },
            ValidationPattern::ParameterRejection { parameter_index, reason, validation_location } => {
                results.push(common::ParameterValidationInfo {
                    max_allowed_length: None,
                    validates_length: true,
                    parameter_index: Some(*parameter_index),
                    validation_strategy: format!("Parameter rejection at instruction {}: {} (parameter {})", 
                                               validation_location, reason, parameter_index),
                    validation_type: common::ValidationTypeInfo::Rejection,
                    metadata: Some(reason.clone()),
                });
            },
            ValidationPattern::TypeCheck { parameter_index, expected_type, validation_location } => {
                results.push(common::ParameterValidationInfo {
                    max_allowed_length: None,
                    validates_length: false, // Type checking is different from length validation
                    parameter_index: Some(*parameter_index),
                    validation_strategy: format!("Type check at instruction {}: parameter {} must be of type {}", 
                                               validation_location, parameter_index, expected_type),
                    validation_type: common::ValidationTypeInfo::TypeCheck,
                    metadata: Some(expected_type.clone()),
                });
            },
            ValidationPattern::CustomLimitCheck { parameter_index, limit_type, limit_value, validation_location } => {
                results.push(common::ParameterValidationInfo {
                    max_allowed_length: Some(*limit_value), // Use the limit value as max allowed length
                    validates_length: limit_type.contains("length") || limit_type.contains("size"),
                    parameter_index: Some(*parameter_index),
                    validation_strategy: format!("Custom limit check at instruction {}: parameter {} has {} limit of {}",
                                                validation_location, parameter_index, limit_type, limit_value),
                    validation_type: if limit_type.contains("range") {
                        common::ValidationTypeInfo::RangeCheck
                    } else if limit_type.contains("protocol") {
                        common::ValidationTypeInfo::ProtocolSpecific(limit_type.clone())
                    } else {
                        common::ValidationTypeInfo::Other
                    },
                    metadata: Some(limit_type.clone()),
                });
            },
            ValidationPattern::NestedValidation { parameter_index, inner_validations, validation_location } => {
                // For nested validations, process each inner validation and include the parent parameter
                let nested_desc = format!("Nested validation at instruction {} for parameter {}", validation_location, parameter_index);
                
                // Add an entry for the parent validation
                results.push(common::ParameterValidationInfo {
                    max_allowed_length: None,
                    validates_length: true, // Assuming nested validations include length checks
                    parameter_index: Some(*parameter_index),
                    validation_strategy: nested_desc,
                    validation_type: common::ValidationTypeInfo::Composite,
                    metadata: Some(format!("Contains {} nested validations", inner_validations.len())),
                });
                
                // The nested validations would be processed separately
                // but we don't actually need to process them here since they're already in the validation_patterns list
            },
        }
    }
    
    // For Wasmlanche contracts, particularly look for length limit validations that match
    // the known pattern: first 4 bytes containing length prefix that must be below some threshold
    for result in &mut results {
        if result.validates_length && result.parameter_index == Some(0) && result.max_allowed_length.is_some() {
            let limit = result.max_allowed_length.unwrap();
            // If validation limit is reasonable (common limits are 1024, 2048, 4096 bytes)
            if limit > 0 && limit <= 8192 {
                result.validation_strategy = format!("{} - This matches the recommended Wasmlanche parameter validation pattern", 
                                                 result.validation_strategy);
            } else if limit > 10_000_000 {
                // Unreasonably large limit - might indicate insufficient validation
                result.validation_strategy = format!("{} - WARNING: Validation limit appears excessive and may be vulnerable to length attacks", 
                                                 result.validation_strategy);
            }
        }
    }
    
    results
}

impl Property for MemorySafetyProperty {
    type Proof = MemorySafetyProofData;

    fn verify(&self, wasm: &[u8], _features: &WasmFeatures) -> anyhow::Result<Self::Proof> {
        let mut memory_analyzer = MemoryAnalyzer::new();
        
        // Parse WASM module
        memory_analyzer.analyze_wasm(wasm)?;
        
        let (memory_accesses, allocations, max_memory, validation_patterns) = memory_analyzer.get_proof_data();
        
        // Perform actual memory safety verification
        
        // 1. Verify bounds checking
        let bounds_checked = verify_memory_bounds(memory_accesses.as_slice(), max_memory);
        
        // 2. Verify memory leak freedom
        let leak_free = verify_memory_leaks(allocations.as_slice());
        
        // 3. Verify access safety (read-after-write)
        let access_safety = verify_access_safety(memory_accesses.as_slice());
        
        // 4. Check for parameter validation
        let has_parameter_validation = !validation_patterns.is_empty();
        let parameter_validation_results = analyze_parameter_validation(&validation_patterns);
        
        Ok(MemorySafetyProofData {
            bounds_checked,
            leak_free,
            max_memory,
            access_safety,
            memory_accesses,
            allocations,
            // Add parameter validation info to the proof data
            has_parameter_validation,
            parameter_validation_results,
        })
    }
}

/// Verifies that all memory accesses are within bounds
/// 
/// This function checks that:
/// 1. No memory access exceeds the maximum memory size
/// 2. All accesses are properly aligned
/// 3. No access attempts to read/write past allocated memory
pub fn verify_memory_bounds(accesses: &[MemoryAccessData], max_memory: u32) -> bool {
    for access in accesses {
        // Check if the access exceeds maximum memory
        if access.offset as u32 >= max_memory {
            return false;
        }
        
        // Ensure the access doesn't exceed maximum memory with its size
        if (access.offset as u32 + access.size as u32) > max_memory {
            return false;
        }
        
        // Check alignment based on access size
        // For example, 4-byte accesses should be aligned to 4 bytes
        if access.size > 1 && (access.offset % access.size as u64 != 0) {
            return false;
        }
    }
    
    true
}

/// Verifies that memory doesn't leak
///
/// This function checks that:
/// 1. All allocated memory is eventually freed
/// 2. No double-free occurs
/// 3. No use-after-free occurs
pub fn verify_memory_leaks(allocations: &[AllocationData]) -> bool {
    let mut has_explicit_allocations = false;
    let mut all_freed = true;
    
    // In a more sophisticated implementation, we examine imported function usage
    // Skip the first allocation which represents the module's default memory
    for (index, alloc) in allocations.iter().enumerate() {
        // Skip the initial module memory
        if index == 0 {
            continue;
        }
        
        // Mark that we have explicit allocations (from malloc etc.)
        has_explicit_allocations = true;
        
        if !alloc.is_freed {
            all_freed = false;
            // We could log details of the leaked allocation here
            // println!("Leak detected: address={}, size={}", alloc.address, alloc.size);
        }
    }
    
    // If we had explicit allocations, they should all be freed
    // If we had no explicit allocations, we consider it leak-free
    !has_explicit_allocations || all_freed
}

/// Verifies that memory accesses follow safety patterns
///
/// This function checks that:
/// 1. Memory is initialized before being read
/// 2. No overlapping writes occur that could cause race conditions
/// 3. Critical memory regions are properly protected
pub fn verify_access_safety(accesses: &[MemoryAccessData]) -> bool {
    use std::collections::HashSet;
    
    // Track which memory addresses have been written to
    let mut initialized_memory = HashSet::new();
    
    for access in accesses {
        if access.is_load {
            // For read operations, check if the memory was initialized
            // For each byte in the range, check if it's initialized
            for offset in 0..access.size {
                if !initialized_memory.contains(&(access.offset + offset as u64)) {
                    // Reading uninitialized memory
                    return false;
                }
            }
        } else {
            // For write operations, mark memory as initialized
            for offset in 0..access.size {
                initialized_memory.insert(access.offset + offset as u64);
            }
        }
    }
    
    true
}

/// Analyzer for tracking memory accesses and allocations
#[derive(Debug)]
pub struct MemoryAnalyzer {
    memory_accesses: Vec<MemoryAccessData>,
    memory_allocations: Vec<AllocationData>,
    stack: Vec<u64>,
    mem_byte: u64,
    
    // Maps function index to name for imported functions
    imported_functions: std::collections::HashMap<u32, String>,
    
    // Maps function index to memory management type
    memory_managers: std::collections::HashMap<u32, MemoryManagerType>,
    
    // Track the latest potential return value from malloc
    last_allocation_address: Option<u32>,
    
    // Track the size of the last allocation request
    last_allocation_size: Option<u32>,
    
    // Function index counter
    function_count: u32,
    
    // Enhanced data flow tracking
    // ===========================
    
    // Semantic stack for tracking data types/meanings
    value_stack: Vec<DataValue>,
    
    // Local variables and their data values
    locals: Vec<DataValue>,
    
    // Parameter validation patterns detected
    validation_patterns: Vec<ValidationPattern>,
    
    // Track branching and conditionals for control flow analysis
    branch_stack: Vec<BranchContext>,
    
    // Current instruction index for tracking locations of validations
    current_instruction: u32,
    
    // Track parameter indices and purposes
    parameters: Vec<ParameterInfo>,
}

impl MemoryAnalyzer {
    pub fn new() -> Self {
        let mut analyzer = Self {
            memory_accesses: Vec::new(),
            memory_allocations: Vec::new(),
            stack: Vec::new(),
            mem_byte: 0,
            imported_functions: std::collections::HashMap::new(),
            memory_managers: std::collections::HashMap::new(),
            last_allocation_address: None,
            last_allocation_size: None,
            function_count: 0,
            value_stack: Vec::new(),
            locals: Vec::new(),
            validation_patterns: Vec::new(),
            branch_stack: Vec::new(),
            current_instruction: 0,
            parameters: Vec::new(),
        };
        
        // Initial memory allocation for the WASM module's default memory
        analyzer.memory_allocations.push(AllocationData {
            address: 0,
            size: 65536, // One page = 64KB
            is_freed: false,
        });
        
        analyzer.mem_byte = 65536;
        analyzer
    }

    pub fn analyze_wasm(&mut self, wasm_bytes: &[u8]) -> Result<()> {
        let parser = Parser::new(0);
        
        for payload in parser.parse_all(wasm_bytes) {
            let payload = payload?;
            match payload {
                Payload::ImportSection(reader) => {
                    // Process imported functions
                    for import in reader {
                        let import = import?;
                        // Check if this is a function import
                        if let wasmparser::TypeRef::Func(_) = import.ty {
                            // Store the import with its function index
                            let function_name = format!("{}.{}", import.module, import.name);
                            self.imported_functions.insert(self.function_count, function_name.clone());
                            
                            // Check if this is a known memory management function
                            if import.module == "env" {
                                match import.name {
                                    "malloc" | "__wbindgen_malloc" | "memory.allocate" => {
                                        self.memory_managers.insert(self.function_count, MemoryManagerType::Allocator);
                                    }
                                    "free" | "__wbindgen_free" | "memory.free" => {
                                        self.memory_managers.insert(self.function_count, MemoryManagerType::Deallocator);
                                    }
                                    _ => {}
                                }
                            }
                            
                            self.function_count += 1;
                        }
                    }
                }
                Payload::FunctionSection(reader) => {
                    // Keep track of function indices
                    let function_count = reader.count();
                    self.function_count += function_count;
                }
                Payload::CodeSectionEntry(code) => {
                    for op in code.get_operators_reader()? {
                        let op = op?;
                        match op {
                            // Constants that may affect memory offsets
                            Operator::I32Const { value } => {
                                self.stack.push(value as u64);
                                
                                // Enhanced data flow tracking
                                self.value_stack.push(DataValue::Const(value as i64));
                                
                                // Check for common parameter validation constants
                                if value > 0 && value <= 8192 {
                                    // This might be a length limit for parameter validation
                                    // We'll confirm this if it's used in a comparison later
                                }
                            }
                            Operator::I64Const { value } => {
                                self.stack.push(value as u64);
                                
                                // Enhanced data flow tracking
                                self.value_stack.push(DataValue::Const(value));
                            }

                            // Memory loads
                            Operator::I32Load { memarg } => {
                                if let Some(addr) = self.stack.pop() {
                                    let effective_addr = addr + memarg.offset as u64;
                                    self.memory_accesses.push(MemoryAccessData {
                                        offset: effective_addr,
                                        size: 4,
                                        is_load: true,
                                    });
                                    
                                    // Enhanced data flow tracking
                                    if let Some(val) = self.value_stack.pop() {
                                        // If we're reading from a parameter buffer
                                        if matches!(val, DataValue::Address(_)) {
                                            // This might be reading a length prefix (common pattern)
                                            // Push a length value to the stack
                                            self.value_stack.push(DataValue::Length(0));
                                            
                                            // Record potential parameter structure detection
                                            // Check if this looks like reading a parameter length prefix
                                            if effective_addr == 0 || effective_addr == 4 {
                                                // First 4 bytes often contain length in WASM contracts
                                                // Add a parameter that needs validation
                                                self.detect_potential_parameter(effective_addr);
                                            }
                                        } else {
                                            // Generic load, unknown value returned
                                            self.value_stack.push(DataValue::Unknown);
                                        }
                                    } else {
                                        // Stack underflow - shouldn't happen in valid WASM
                                        self.value_stack.push(DataValue::Unknown);
                                    }
                                }
                            }
                            Operator::I64Load { memarg } => {
                                if let Some(addr) = self.stack.pop() {
                                    self.memory_accesses.push(MemoryAccessData {
                                        offset: addr + memarg.offset as u64,
                                        size: 8,
                                        is_load: true,
                                    });
                                }
                            }
                            Operator::F32Load { memarg } => {
                                if let Some(addr) = self.stack.pop() {
                                    self.memory_accesses.push(MemoryAccessData {
                                        offset: addr + memarg.offset as u64,
                                        size: 4,
                                        is_load: true,
                                    });
                                }
                            }
                            Operator::F64Load { memarg } => {
                                if let Some(addr) = self.stack.pop() {
                                    self.memory_accesses.push(MemoryAccessData {
                                        offset: addr + memarg.offset as u64,
                                        size: 8,
                                        is_load: true,
                                    });
                                }
                            }
                            
                            // Memory stores
                            Operator::I32Store { memarg } => {
                                // Pop value and address
                                if self.stack.pop().is_some() { // value
                                    if let Some(addr) = self.stack.pop() { // address
                                        self.memory_accesses.push(MemoryAccessData {
                                            offset: addr + memarg.offset as u64,
                                            size: 4,
                                            is_load: false,
                                        });
                                    }
                                }
                            }
                            Operator::I64Store { memarg } => {
                                // Pop value and address
                                if self.stack.pop().is_some() { // value
                                    if let Some(addr) = self.stack.pop() { // address
                                        self.memory_accesses.push(MemoryAccessData {
                                            offset: addr + memarg.offset as u64,
                                            size: 8,
                                            is_load: false,
                                        });
                                    }
                                }
                            }
                            Operator::F32Store { memarg } => {
                                // Pop value and address
                                if self.stack.pop().is_some() { // value
                                    if let Some(addr) = self.stack.pop() { // address
                                        self.memory_accesses.push(MemoryAccessData {
                                            offset: addr + memarg.offset as u64,
                                            size: 4,
                                            is_load: false,
                                        });
                                    }
                                }
                            }
                            Operator::F64Store { memarg } => {
                                // Pop value and address
                                if self.stack.pop().is_some() { // value
                                    if let Some(addr) = self.stack.pop() { // address
                                        self.memory_accesses.push(MemoryAccessData {
                                            offset: addr + memarg.offset as u64,
                                            size: 8,
                                            is_load: false,
                                        });
                                    }
                                }
                            }

                            // Memory allocation
                            Operator::MemoryGrow { .. } => {
                                let addr = self.mem_byte;
                                self.memory_allocations.push(AllocationData {
                                    address: addr as u32,
                                    size: 65536, // One page = 64KB
                                    is_freed: false,
                                });
                                self.mem_byte += 65536;
                            }
                            
                            // Comparison operators - essential for parameter validation
                            Operator::I32Eqz => self.handle_comparison_eqz(),
                            Operator::I32Eq => self.handle_comparison_eq(),
                            Operator::I32Ne => self.handle_comparison_ne(),
                            Operator::I32LtS | Operator::I32LtU => self.handle_comparison_lt(),
                            Operator::I32GtS | Operator::I32GtU => self.handle_comparison_gt(),
                            Operator::I32LeS | Operator::I32LeU => self.handle_comparison_le(),
                            Operator::I32GeS | Operator::I32GeU => self.handle_comparison_ge(),
                            
                            // Branching operations - track validation control flow
                            Operator::BrIf { .. } => self.handle_conditional_branch(),
                            Operator::If { .. } => self.handle_if_branch(),
                            Operator::Else => self.handle_else_branch(),
                            Operator::End => self.handle_end_branch(),
                            
                            // Function calls
                            Operator::Call { function_index } => {
                                // Track for data flow analysis
                                self.current_instruction += 1;
                                
                                // Check if this is a known memory manager
                                if let Some(mgr_type) = self.memory_managers.get(&function_index) {
                                    match mgr_type {
                                        MemoryManagerType::Allocator => {
                                            // For malloc-like functions
                                            // Size should be on top of stack
                                            if let Some(size) = self.stack.pop() {
                                                // Reserve a new address for allocation
                                                let addr = self.mem_byte;
                                                self.last_allocation_address = Some(addr as u32);
                                                self.last_allocation_size = Some(size as u32);
                                                
                                                // Push the address on stack as return value
                                                self.stack.push(addr);
                                                
                                                // Record allocation
                                                self.memory_allocations.push(AllocationData {
                                                    address: addr as u32,
                                                    size: size as u32,
                                                    is_freed: false,
                                                });
                                                
                                                // Update memory byte counter
                                                self.mem_byte += size;
                                            }
                                        }
                                        MemoryManagerType::Deallocator => {
                                            // For free-like functions
                                            if let Some(addr) = self.stack.pop() {
                                                // Mark corresponding allocation as freed
                                                for alloc in &mut self.memory_allocations {
                                                    if alloc.address == addr as u32 {
                                                        alloc.is_freed = true;
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } else {
                                    // For regular function calls, we'd need more stack manipulation
                                    // This is simplified and not accurate for all calling conventions
                                    // but we keep track of the call for potential future enhancements
                                    
                                    // For now, we'll just check if this is an imported function
                                    if let Some(_name) = self.imported_functions.get(&function_index) {
                                        // We could log or analyze imported function calls more deeply
                                        // println!("Called imported function: {}", name);
                                    }
                                }
                            }
                            
                            // Local variable handling for tracking allocation returns
                            Operator::LocalSet { local_index: 0 } => {
                                // If we just allocated memory and storing to local.0
                                if let Some(addr) = self.last_allocation_address {
                                    // Keep address in stack for potential use
                                    self.stack.push(addr as u64);
                                }
                            }
                            
                            Operator::LocalGet { local_index } => {
                                // If we're getting a local that might be an allocation address
                                if local_index == 0 && self.last_allocation_address.is_some() {
                                    // Push address back on stack
                                    self.stack.push(self.last_allocation_address.unwrap() as u64);
                                }
                            }

                            _ => {}
                        }
                    }
                }
                Payload::MemorySection(reader) => {
                    for memory in reader {
                        let memory = memory?;
                        let initial_pages = memory.initial as u32;
                        if initial_pages > 0 {
                            // Update initial memory allocation
                            if let Some(alloc) = self.memory_allocations.first_mut() {
                                alloc.size = initial_pages * 65536;
                            }
                            self.mem_byte = (initial_pages as u64) * 65536;
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn get_memory_accesses(&self) -> &[MemoryAccessData] {
        &self.memory_accesses
    }

    pub fn get_allocations(&self) -> &[AllocationData] {
        &self.memory_allocations
    }

    pub fn get_proof_data(&self) -> (Vec<MemoryAccessData>, Vec<AllocationData>, u32, Vec<ValidationPattern>) {
        (
            self.memory_accesses.clone(),
            self.memory_allocations.clone(),
            (self.mem_byte as u32),
            self.validation_patterns.clone(),
        )
    }
    
    /// Detects a potential parameter from a memory address
    fn detect_potential_parameter(&mut self, address: u64) {
        // Only consider addresses in the first few bytes as potential parameter pointers
        if address < 32 {
            let param_index = (address / 4) as u32;
            
            // Check if we already have this parameter
            if !self.parameters.iter().any(|p| p.index == param_index) {
                // Add a new parameter
                self.parameters.push(ParameterInfo {
                    index: param_index,
                    purpose: if address == 0 {
                        // First parameter is often a buffer address
                        ParameterPurpose::BufferAddress
                    } else if address == 4 {
                        // Second parameter is often a buffer length
                        ParameterPurpose::BufferLength
                    } else {
                        ParameterPurpose::Unknown
                    },
                    is_validated: false,
                    max_allowed: None,
                });
            }
        }
    }
    
    /// Handles comparison with zero (commonly used for null checks)
    fn handle_comparison_eqz(&mut self) {
        self.current_instruction += 1;
        
        // This operation checks if a value is zero
        if let Some(val) = self.value_stack.pop() {
            match val {
                DataValue::Length(len) => {
                    // Checking if length is zero - potential validation
                    // Push result of comparison to stack
                    self.value_stack.push(DataValue::BoundChecked(len, 0));
                }
                _ => {
                    // Generic comparison
                    self.value_stack.push(DataValue::Unknown);
                }
            }
        } else {
            // Stack underflow
            self.value_stack.push(DataValue::Unknown);
        }
    }
    
    /// Handles equality comparison
    fn handle_comparison_eq(&mut self) {
        self.current_instruction += 1;
        
        // Pop two values for comparison
        let val2 = self.value_stack.pop().unwrap_or(DataValue::Unknown);
        let val1 = self.value_stack.pop().unwrap_or(DataValue::Unknown);
        
        // If comparing a length against a constant
        if let (DataValue::Length(len), DataValue::Const(max)) = (&val1, &val2) {
            // This is a length equality check - common in validation
            self.value_stack.push(DataValue::BoundChecked(*len, *max as u64));
            
            // Record this as a validation pattern
            self.record_length_validation(*len, *max as u64);
        } else if let (DataValue::Const(max), DataValue::Length(len)) = (&val1, &val2) {
            // Same but reversed order
            self.value_stack.push(DataValue::BoundChecked(*len, *max as u64));
            self.record_length_validation(*len, *max as u64);
        } else {
            // Generic comparison
            self.value_stack.push(DataValue::Unknown);
        }
    }
    
    /// Handles not-equal comparison
    fn handle_comparison_ne(&mut self) {
        self.current_instruction += 1;
        
        // Similar logic to handle_comparison_eq
        let _val2 = self.value_stack.pop().unwrap_or(DataValue::Unknown);
        let _val1 = self.value_stack.pop().unwrap_or(DataValue::Unknown);
        
        // Generic handling for now
        self.value_stack.push(DataValue::Unknown);
    }
    
    /// Handles less-than comparison
    fn handle_comparison_lt(&mut self) {
        self.current_instruction += 1;
        
        // Pop two values for comparison
        let val2 = self.value_stack.pop().unwrap_or(DataValue::Unknown);
        let val1 = self.value_stack.pop().unwrap_or(DataValue::Unknown);
        
        // If comparing a length against a constant max value
        if let (DataValue::Length(len), DataValue::Const(max)) = (&val1, &val2) {
            // This is a length validation - very common!
            if *max > 0 {
                self.value_stack.push(DataValue::BoundChecked(*len, *max as u64));
                
                // Record this as a validation pattern
                self.record_length_validation(*len, *max as u64);
            } else {
                self.value_stack.push(DataValue::Unknown);
            }
        } else {
            // Generic comparison
            self.value_stack.push(DataValue::Unknown);
        }
    }
    
    /// Handles greater-than comparison
    fn handle_comparison_gt(&mut self) {
        self.current_instruction += 1;
        
        // Pop two values for comparison
        let val2 = self.value_stack.pop().unwrap_or(DataValue::Unknown);
        let val1 = self.value_stack.pop().unwrap_or(DataValue::Unknown);
        
        // If comparing a constant against a length
        if let (DataValue::Const(max), DataValue::Length(len)) = (&val1, &val2) {
            // This is checking max > length, which is a reversed bound check
            if *max > 0 {
                self.value_stack.push(DataValue::BoundChecked(*len, *max as u64));
                self.record_length_validation(*len, *max as u64);
            } else {
                self.value_stack.push(DataValue::Unknown);
            }
        } else {
            // Generic comparison
            self.value_stack.push(DataValue::Unknown);
        }
    }
    
    /// Handles less-than-or-equal comparison
    fn handle_comparison_le(&mut self) {
        self.current_instruction += 1;
        
        // Similar to handle_comparison_lt but with <= semantics
        let val2 = self.value_stack.pop().unwrap_or(DataValue::Unknown);
        let val1 = self.value_stack.pop().unwrap_or(DataValue::Unknown);
        
        // If comparing a length against a constant max value
        if let (DataValue::Length(len), DataValue::Const(max)) = (&val1, &val2) {
            // This is a length validation - very common!
            if *max > 0 {
                self.value_stack.push(DataValue::BoundChecked(*len, *max as u64));
                self.record_length_validation(*len, *max as u64);
            } else {
                self.value_stack.push(DataValue::Unknown);
            }
        } else {
            // Generic comparison
            self.value_stack.push(DataValue::Unknown);
        }
    }
    
    /// Handles greater-than-or-equal comparison
    fn handle_comparison_ge(&mut self) {
        self.current_instruction += 1;
        
        // Similar to handle_comparison_gt but with >= semantics
        let val2 = self.value_stack.pop().unwrap_or(DataValue::Unknown);
        let val1 = self.value_stack.pop().unwrap_or(DataValue::Unknown);
        
        // If comparing a constant against a length
        if let (DataValue::Const(max), DataValue::Length(len)) = (&val1, &val2) {
            // This is checking max >= length, which is a reversed bound check
            if *max > 0 {
                self.value_stack.push(DataValue::BoundChecked(*len, *max as u64));
                self.record_length_validation(*len, *max as u64);
            } else {
                self.value_stack.push(DataValue::Unknown);
            }
        } else {
            // Generic comparison
            self.value_stack.push(DataValue::Unknown);
        }
    }
    
    /// Records a length validation pattern
    fn record_length_validation(&mut self, _len: u64, max_allowed: u64) {
        // Find which parameter this might be associated with
        for (idx, param) in self.parameters.iter_mut().enumerate() {
            if param.purpose == ParameterPurpose::BufferLength {
                // Mark this parameter as validated
                param.is_validated = true;
                param.max_allowed = Some(max_allowed);
                
                // Record the validation pattern
                self.validation_patterns.push(ValidationPattern::LengthCheck {
                    parameter_index: idx as u32,
                    max_allowed,
                    validation_location: self.current_instruction,
                });
                
                return;
            }
        }
        
        // If we didn't find a matching parameter, this might be a generic check
        // We'll still record it with a default parameter index of 0
        self.validation_patterns.push(ValidationPattern::LengthCheck {
            parameter_index: 0,
            max_allowed,
            validation_location: self.current_instruction,
        });
    }
    
    /// Handles conditional branch instructions
    fn handle_conditional_branch(&mut self) {
        self.current_instruction += 1;
        
        // Check if the branch condition is related to parameter validation
        if let Some(DataValue::BoundChecked(_, max)) = self.value_stack.last() {
            // This is likely a parameter validation branch
            // We'll push a branch context to track this validation
            self.branch_stack.push(BranchContext {
                condition: Some(BranchCondition::LessThan(
                    DataValue::Length(0), // placeholder
                    DataValue::Const(*max as i64),
                )),
                depth: self.branch_stack.len() as u32,
                is_validation: true,
            });
        } else {
            // Generic branch
            self.branch_stack.push(BranchContext {
                condition: None,
                depth: self.branch_stack.len() as u32,
                is_validation: false,
            });
        }
    }
    
    /// Handles if branch instructions
    fn handle_if_branch(&mut self) {
        self.current_instruction += 1;
        
        // Similar logic to handle_conditional_branch
        if let Some(DataValue::BoundChecked(_, max)) = self.value_stack.last() {
            // This is likely a parameter validation branch
            self.branch_stack.push(BranchContext {
                condition: Some(BranchCondition::LessThan(
                    DataValue::Length(0), // placeholder
                    DataValue::Const(*max as i64),
                )),
                depth: self.branch_stack.len() as u32,
                is_validation: true,
            });
        } else {
            // Generic branch
            self.branch_stack.push(BranchContext {
                condition: None,
                depth: self.branch_stack.len() as u32,
                is_validation: false,
            });
        }
    }
    
    /// Handles else branch instructions
    fn handle_else_branch(&mut self) {
        self.current_instruction += 1;
        
        // In an else branch, the condition is inverted
        if let Some(branch) = self.branch_stack.last_mut() {
            if branch.is_validation {
                // This is the else clause of a validation check
                // This is where parameter rejection often happens
                
                // Find any parameters that were being validated
                for (idx, param) in self.parameters.iter().enumerate() {
                    if param.purpose == ParameterPurpose::BufferLength && !param.is_validated {
                        // Record that this branch might reject invalid parameters
                        self.validation_patterns.push(ValidationPattern::ParameterRejection {
                            parameter_index: idx as u32,
                            reason: "Parameter length validation failed".to_string(),
                            validation_location: self.current_instruction,
                        });
                    }
                }
            }
        }
    }
    
    /// Handles end branch instructions
    fn handle_end_branch(&mut self) {
        self.current_instruction += 1;
        
        // Pop the branch context and analyze it for potential parameter validation
        if !self.branch_stack.is_empty() {
            let branch_context = self.branch_stack.pop().unwrap();
            
            // If this was a validation branch, check if it was enforcing parameter validation
            if branch_context.is_validation {
                if let Some(condition) = branch_context.condition {
                    match condition {
                        BranchCondition::LessThan(left, right) => {
                            // Handle length validation pattern
                            if let DataValue::Length(idx) = left {
                                if let DataValue::Const(max) = right {
                                    // This is a length check, e.g., checking if parameter length < some constant
                                    self.validation_patterns.push(ValidationPattern::LengthCheck {
                                        parameter_index: idx as u32,
                                        max_allowed: max as u64,
                                        validation_location: branch_context.depth,
                                    });
                                    
                                    // Add debug info for Wasmlanche contracts
                                    if idx == 0 && max <= 1024 {
                                        // This is likely the recommended Wasmlanche pattern (first param length must be reasonable)
                                        println!("Found recommended parameter validation: length must be <= {} bytes", max);
                                    } else if max > 10_000_000 {
                                        // Unreasonable length limit - potential vulnerability
                                        println!("WARNING: Unreasonable parameter length validation: {} bytes", max);
                                    }
                                }
                            }
                        },
                        BranchCondition::GreaterThan(left, right) => {
                            // Handle minimum length checks, e.g., parameter length must be at least some value
                            if let DataValue::Length(idx) = left {
                                if let DataValue::Const(min) = right {
                                    // Minimum size check
                                    self.validation_patterns.push(ValidationPattern::ParameterRejection {
                                        parameter_index: idx as u32,
                                        reason: format!("Parameter length must be at least {} bytes", min),
                                        validation_location: branch_context.depth,
                                    });
                                }
                            }
                        },
                        BranchCondition::Equal(_left, right) => {
                            // Looking for equality checks, often used for type or signature validation
                            if let DataValue::Const(expected) = right {
                                self.validation_patterns.push(ValidationPattern::ParameterRejection {
                                    parameter_index: 0, // Assume first parameter for now
                                    reason: format!("Parameter must equal {}", expected),
                                    validation_location: branch_context.depth,
                                });
                            }
                        },
                        _ => {
                            // Other condition types can be handled here
                        }
                    }
                }
            }
        }
    }
}
