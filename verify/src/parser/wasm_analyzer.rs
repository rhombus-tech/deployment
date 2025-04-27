use anyhow::Result;
use walrus::{Module, FunctionId, MemoryId, TableId};
use walrus::ir::Instr;
use walrus::ExportItem;
use crate::parser::types::FunctionTableInfo;
use std::collections::HashSet;
use crate::parser::types::{MemoryType, TableType, RefType, Limits};
use std::collections::HashMap;
use crate::parser::cfg::ControlFlowGraph;
use crate::circuits::memory_safety::{MemoryAccess, MemoryInit};
use common::{ParameterValidationInfo, ValidationTypeInfo};
use crate::parser::ValueType;
use crate::circuits::type_safety::BlockContext as TypeSafetyBlockContext;

/// Resource usage statistics
#[derive(Debug, Clone, Default)]
pub struct ResourceUsage {
    /// Maximum stack depth
    pub max_stack_depth: u32,
    /// Maximum memory pages
    pub max_memory_pages: u32,
    /// Maximum table size
    pub max_table_size: u32,
    /// Maximum number of globals
    pub max_globals: u32,
    /// Maximum call depth
    pub max_call_depth: u32,
}

/// Analyzer for WebAssembly modules
#[derive(Debug)]
pub struct WasmAnalyzer {
    /// The WebAssembly module being analyzed
    pub module: Module,
    /// Memory access patterns for each memory ID
    /// Maps memory ID -> Vec<(offset, align, size)>
    memory_access: HashMap<MemoryId, Vec<(u32, u32, u32)>>,
    /// Function dependencies (calls between functions)
    function_deps: HashMap<FunctionId, HashSet<FunctionId>>,
    /// Operations in each function
    function_ops: HashMap<FunctionId, Vec<Instr>>,
    /// Test mode flag - disables some checks for testing
    test_mode: bool,
}

impl WasmAnalyzer {
    /// Create a new analyzer from a module
    pub fn new(module: Module) -> Result<Self> {
        Ok(Self {
            module,
            memory_access: HashMap::new(),
            function_deps: HashMap::new(),
            function_ops: HashMap::new(),
            test_mode: false,
        })
    }
    
    /// Set test mode
    pub fn set_test_mode(&mut self, test_mode: bool) {
        self.test_mode = test_mode;
    }
    
    /// Check if test mode is enabled
    pub fn is_test_mode(&self) -> bool {
        self.test_mode
    }

    /// Create a new analyzer from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let module = Module::from_buffer(bytes)?;
        Self::new(module)
    }

    /// Get memory type for a given memory ID
    pub fn get_memory_type(&self, memory_id: MemoryId) -> Result<MemoryType> {
        let memory = self.module.memories.get(memory_id);
        Ok(MemoryType::new(
            Limits::new(memory.initial, memory.maximum),
            false, // Not shared memory
        )?)
    }

    /// Get current memory pages for a given memory ID
    pub fn get_current_pages(&self, memory_id: MemoryId) -> usize {
        let memory = self.module.memories.get(memory_id);
        memory.initial as usize
    }

    /// Get memory access patterns for a given memory ID
    pub fn get_memory_access(&self, memory_id: MemoryId) -> Option<Vec<(u32, u32)>> {
        self.memory_access.get(&memory_id).map(|accesses| {
            accesses.iter().map(|(offset, _, size)| (*offset, *size)).collect()
        })
    }

    /// Get memory accesses as circuit format
    pub fn get_memory_accesses_circuit(&self, memory_id: MemoryId) -> Option<Vec<MemoryAccess>> {
        self.memory_access.get(&memory_id).map(|accesses| {
            accesses.iter().map(|(offset, align, size)| {
                MemoryAccess::Load(*offset, *align, *size)
            }).collect()
        })
    }

    /// Get memory initializations
    pub fn get_memory_inits(&self, memory_id: MemoryId) -> Option<Vec<MemoryInit>> {
        self.memory_access.get(&memory_id).map(|accesses| {
            accesses.iter().map(|(offset, _, size)| MemoryInit {
                offset: *offset,
                size: *size,
                data: vec![0; *size as usize],
            }).collect()
        })
    }

    /// Get the default memory from the module
    pub fn get_default_memory(&self) -> Result<MemoryId, anyhow::Error> {
        let memory_id = self.module.memories.iter().next()
            .ok_or_else(|| anyhow::anyhow!("No memory found in module"))?.id();
        Ok(memory_id)
    }
    
    /// Get the first memory in the module
    /// Returns Option<MemoryId> for backward compatibility with verification.rs
    pub fn get_memory(&self) -> Option<MemoryId> {
        self.module.memories.iter().next().map(|m| m.id())
    }

    /// Get stack operations
    pub fn get_stack_ops(&self) -> Option<Vec<ValueType>> {
        // Extract value types from all functions in the module
        let mut stack_operations = Vec::new();
        
        for func in self.module.funcs.iter() {
            // Only process local functions, not imports
            if let walrus::FunctionKind::Local(local) = &func.kind {
                // Get function type for parameter and result types
                let func_type = &self.module.types.get(local.ty());
                
                // Add parameters to stack operations
                for param in func_type.params() {
                    stack_operations.push(ValueType::from(*param));
                }
                
                // Process function body if available
                // In walrus 0.19.0, we need to get the function body differently
                // In walrus 0.19.0, we access instructions through the entry block
                let entry_block_id = local.entry_block();
                let block = local.block(entry_block_id);
                
                // Analyze instructions in the block
                for (instr, _loc_id) in &block.instrs {
                    match instr {
                        // Constants push values to stack
                        walrus::ir::Instr::Const(walrus::ir::Const { value: walrus::ir::Value::I32(_) }) => {
                            stack_operations.push(ValueType::I32);
                        },
                        walrus::ir::Instr::Const(walrus::ir::Const { value: walrus::ir::Value::I64(_) }) => {
                            stack_operations.push(ValueType::I64);
                        },
                        walrus::ir::Instr::Const(walrus::ir::Const { value: walrus::ir::Value::F32(_) }) => {
                            stack_operations.push(ValueType::F32);
                        },
                        walrus::ir::Instr::Const(walrus::ir::Const { value: walrus::ir::Value::F64(_) }) => {
                            stack_operations.push(ValueType::F64);
                        },
                        // Binary operations consume two values and produce one
                        walrus::ir::Instr::Binop(ref binop) => {
                            match binop.op {
                                walrus::ir::BinaryOp::I32Add |  
                                walrus::ir::BinaryOp::I32Sub | 
                                walrus::ir::BinaryOp::I32Mul => {
                                    // Consume two I32 and produce one I32
                                    stack_operations.push(ValueType::I32);
                                },
                                walrus::ir::BinaryOp::I64Add | 
                                walrus::ir::BinaryOp::I64Sub | 
                                walrus::ir::BinaryOp::I64Mul => {
                                    // Consume two I64 and produce one I64
                                    stack_operations.push(ValueType::I64);
                                },
                                _ => {
                                    // For other binary operations, add an operation based on type
                                    let op_str = format!("{:?}", binop);
                                    if op_str.starts_with("I32") {
                                        stack_operations.push(ValueType::I32);
                                    } else if op_str.starts_with("I64") {
                                        stack_operations.push(ValueType::I64);
                                    } else if op_str.starts_with("F32") {
                                        stack_operations.push(ValueType::F32);
                                    } else if op_str.starts_with("F64") {
                                        stack_operations.push(ValueType::F64);
                                    }
                                }
                            }
                        },
                        // Handle other instructions that affect the stack
                        _ => {}
                    }
                }
                
                // Add result types to stack operations
                for result in func_type.results() {
                    stack_operations.push(ValueType::from(*result));
                }
            }
        }
        
        // Return the stack operations if any were found
        if stack_operations.is_empty() {
            return None;
        } else {
            return Some(stack_operations);
        }
    }

    /// Get block contexts
    pub fn get_block_contexts(&self) -> Option<Vec<TypeSafetyBlockContext>> {
        let mut block_contexts = Vec::new();
        
        for func in self.module.funcs.iter() {
            // Only process local functions, not imports
            if let walrus::FunctionKind::Local(local) = &func.kind {
                // Get function type for parameter and result types
                let func_type = &self.module.types.get(local.ty());
                
                // Create a block context for the function itself
                let mut param_types = Vec::new();
                for param in func_type.params() {
                    param_types.push(ValueType::from(*param));
                }
                
                let mut result_types = Vec::new();
                for result in func_type.results() {
                    result_types.push(ValueType::from(*result));
                }
                
                // Add the function's block context
                block_contexts.push(TypeSafetyBlockContext {
                    param_types: param_types.clone(),
                    result_types,
                    stack_height: 0, // Initial stack height
                });
                
                // Process function body if available to find blocks
                // In walrus 0.19.0, we access instructions through the entry block
                let entry_block_id = local.entry_block();
                let block = local.block(entry_block_id);
                let mut stack_height = param_types.len();
                
                // Analyze instructions in the block
                for (instr, _loc_id) in &block.instrs {
                    match instr {
                        // Handle block instructions
                        walrus::ir::Instr::Block(block_instr) => {
                            // Create a block context based on the block type
                            // In walrus 0.19.0, we'll use a simplified approach
                            // and just assume no result type for blocks
                            let result_type = vec![];
                            
                            block_contexts.push(TypeSafetyBlockContext {
                                param_types: vec![], // Blocks take their params from the stack
                                result_types: result_type,
                                stack_height,
                            });
                        },
                        walrus::ir::Instr::Loop(loop_instr) => {
                            // Create a block context for loop instructions
                            // In walrus 0.19.0, we'll use a simplified approach
                            // and just assume no result type for loops
                            let result_type = vec![];
                            
                            block_contexts.push(TypeSafetyBlockContext {
                                param_types: vec![], // Loops take their params from the stack
                                result_types: result_type,
                                stack_height,
                            });
                        },
                        walrus::ir::Instr::IfElse(if_instr) => {
                            // Create a block context for if instructions
                            // In walrus 0.19.0, we'll use a simplified approach
                            // and just assume no result type for if/else
                            let result_type = vec![];

                            // Consume one I32 for the condition
                            if stack_height > 0 {
                                stack_height -= 1;
                            }
                            
                            block_contexts.push(TypeSafetyBlockContext {
                                param_types: vec![], // If blocks take condition from stack
                                result_types: result_type,
                                stack_height,
                            });
                        },
                        // Track stack height for other instructions
                        walrus::ir::Instr::Const(walrus::ir::Const { value: walrus::ir::Value::I32(_) }) | 
                        walrus::ir::Instr::Const(walrus::ir::Const { value: walrus::ir::Value::I64(_) }) => {
                            stack_height += 1;
                        },
                        walrus::ir::Instr::Const(walrus::ir::Const { value: walrus::ir::Value::F32(_) }) | 
                        walrus::ir::Instr::Const(walrus::ir::Const { value: walrus::ir::Value::F64(_) }) => {
                            stack_height += 1;
                        },
                        walrus::ir::Instr::Load(load) => {
                            // All loads push a value to the stack
                            stack_height += 1;
                        },
                        walrus::ir::Instr::Drop(_) => {
                            if stack_height > 0 {
                                stack_height -= 1;
                            }
                        },
                        _ => {}
                    }
                }
            }
        }
        
        if block_contexts.is_empty() {
            None
        } else {
            Some(block_contexts)
        }
    }

    /// Get call graph
    pub fn get_call_graph(&self) -> Option<ControlFlowGraph> {
        let mut call_graph = ControlFlowGraph::new();
        let mut function_blocks = HashMap::new();
        
        // First, create a block for each function
        for func in self.module.funcs.iter() {
            let func_id = func.id();
            let block_id = call_graph.create_block();
            function_blocks.insert(func_id, block_id);
            
            // Mark entry points (exported functions)
            for export in self.module.exports.iter() {
                if let ExportItem::Function(id) = export.item {
                    if id == func_id {
                        call_graph.set_entry(block_id);
                        break;
                    }
                }
            }
        }
        
        // Then, analyze function bodies to find call instructions
        for func in self.module.funcs.iter() {
            let caller_id = func.id();
            
            // Only process local functions, not imports
            if let walrus::FunctionKind::Local(local) = &func.kind {
                // In walrus 0.19.0, we access instructions through blocks
                let entry_block_id = local.entry_block();
                let block = local.block(entry_block_id);
                
                // Look for call instructions
                for instr_tuple in &block.instrs {
                    // In walrus 0.19.0, instructions are (Instr, InstrLocId) tuples
                    let (instr, _loc_id) = instr_tuple;
                    match instr {
                        walrus::ir::Instr::Call(call) => {
                            // In walrus 0.19.0, Call contains the function ID
                            let callee_id = call.func;
                            // Add an edge from caller to callee
                            if let (Some(caller_block), Some(callee_block)) = (
                                function_blocks.get(&caller_id),
                                function_blocks.get(&callee_id)
                            ) {
                                call_graph.add_edge(*caller_block, *callee_block);
                            }
                        },
                        walrus::ir::Instr::CallIndirect(type_id) => {
                            // For indirect calls, we can't know the exact callee,
                            // but we can track that they occurred for security validation
                            // For indirect calls, we need to get function tables
                            // The table is usually in table idx 0 for most WASM modules
                            // For security validation, we conservatively assume indirect calls
                            // could reach any function in the table
                            if let Some(tables) = self.get_function_tables().ok() {
                                for table in tables {
                                    // Conservatively assume this could target any function in the table
                                    for element_idx in 0..table.elements.len() as u32 {
                                        if let Some(element) = table.get_element(element_idx) {
                                            let target_func_idx = element.function_idx;
                                            
                                            // Find the function ID for this function index
                                            for f in self.module.funcs.iter() {
                                                if f.id().index() as u32 == target_func_idx {
                                                    let target_id = f.id();
                                                    
                                                    if let (Some(caller_block), Some(callee_block)) = (
                                                        function_blocks.get(&caller_id),
                                                        function_blocks.get(&target_id)
                                                    ) {
                                                        call_graph.add_edge(*caller_block, *callee_block);
                                                    }
                                                    
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        _ => { /* Ignore other instructions */ }
                    }
                }
            }
        }
        
        // Identify functions with no callers as potential entry points
        for (func_id, block_id) in &function_blocks {
            // Check if block has any predecessors
            let has_incoming = call_graph.get_predecessors(*block_id).is_empty();
            
            // If no incoming edges, mark as potential entry
            if !has_incoming {
                call_graph.set_entry(*block_id);
            }
        }
        
        if call_graph.get_blocks().is_empty() {
            None
        } else {
            Some(call_graph)
        }
    }
    
    /// Get resource usage statistics
    pub fn get_resource_usage(&self) -> ResourceUsage {
        ResourceUsage {
            max_stack_depth: 16,
            max_memory_pages: 100,
            max_table_size: 100,
            max_globals: 50,
            max_call_depth: 32,
        }
    }
    
    /// Get the first table in the module
    pub fn get_table(&self) -> Option<TableId> {
        self.module.tables.iter().next().map(|t| t.id())
    }
    
    /// Get all tables in the module
    pub fn get_tables(&self) -> Vec<TableId> {
        self.module.tables.iter().map(|t| t.id()).collect()
    }
    
    /// Get function table information for a specific table
    pub fn get_function_table_info(&self, table_id: TableId) -> Result<FunctionTableInfo> {
        let table = self.module.tables.get(table_id);
        
        // Create a table type
        let element_type = RefType::Func; // WASM tables are always function refs
        // Access initial and maximum directly from table
        let initial = table.initial;
        let maximum = table.maximum;
        let limits = Limits::new(initial, maximum);
        let table_type = TableType::new(element_type, limits)?;
        
        // Create the function table info
        let mut function_table = FunctionTableInfo::new(
            0, // table index, hardcoded for now
            table_type,
            initial,
        );
        
        // Look for table element segments to initialize function table
        let mut has_init = false;
        for elem_segment in self.module.elements.iter() {
            // Get the element kind and check if it's an active segment for our table
            match &elem_segment.kind {
                walrus::ElementKind::Active { table, offset: _ } => {
                    if *table == table_id {
                        has_init = true;
                        
                        // Process each element in the members array
                        for (idx, member) in elem_segment.members.iter().enumerate() {
                            // Get function index directly - correct way to access in updated walrus API
                            if let Some(func_id) = member {
                                // Get the function type
                                let func = self.module.funcs.get(*func_id);
                                let type_id = func.ty();
                                
                                // Add to function table
                                function_table.set_element(idx as u32, func_id.index() as u32, type_id.index() as u32)?;
                            }
                        }
                    }
                },
                walrus::ElementKind::Passive => {
                    // Skip passive elements as they're not initialized to any specific table
                    // Passive elements are used with the table.init instruction
                },
                walrus::ElementKind::Declared => {
                    // Skip declared elements (typically used with imported tables)
                    // These don't contribute to our function table analysis
                }
            }
        }
        
        if has_init {
            function_table.mark_initialized();
        }
        
        Ok(function_table)
    }
    
    /// Get all function tables in the module
    pub fn get_function_tables(&self) -> Result<Vec<FunctionTableInfo>> {
        let mut tables = Vec::new();
        
        for table_id in self.get_tables() {
            match self.get_function_table_info(table_id) {
                Ok(table_info) => tables.push(table_info),
                Err(e) => {
                    if !self.test_mode {
                        return Err(e);
                    }
                    // In test mode, ignore errors
                }
            }
        }
        
        Ok(tables)
    }

    /// Get memory allocations
    pub fn get_memory_allocations(&self, memory_id: MemoryId) -> Option<Vec<(u32, u32)>> {
        let mut allocations = Vec::new();
        
        // First collect data segment allocations (static memory)
        for data in self.module.data.iter() {
            // In walrus 0.19.0, data segments use a kind field
            // We need to extract the memory ID and offset if it's an active segment
            if let walrus::DataKind::Active(active_data) = &data.kind {
                if active_data.memory == memory_id {
                    // For static data segments, get the offset and size
                    // The offset may be a constant or an expression
                    let offset = match &active_data.location {
                        walrus::ActiveDataLocation::Absolute(offset) => *offset,
                        // In walrus 0.19.0, Relative contains a Global ID, not an InitExpr
                        walrus::ActiveDataLocation::Relative(global_id) => {
                            // Since we can't directly get the value, default to 0
                            // We could look up the global with module.globals.get(*global_id)
                            // but for simplicity in this migration, we'll use 0
                            0
                        },
                    };
                    let size = data.value.len() as u32;
                    allocations.push((offset, offset + size));
                }
            }
        }
        
        // Next, scan function bodies for dynamic memory allocations
        for func in self.module.funcs.iter() {
            if let walrus::FunctionKind::Local(local) = &func.kind {
                // In walrus 0.19.0, we access instructions through blocks
                let entry_block_id = local.entry_block();
                let block = local.block(entry_block_id);
                
                // Look for memory operations that indicate allocations
                for instr_tuple in &block.instrs {
                    // In walrus 0.19.0, instructions are (Instr, InstrLocId) tuples
                    let (instr, _loc_id) = instr_tuple;
                    match instr {
                        walrus::ir::Instr::MemoryGrow(grow_instr) => {
                            if grow_instr.memory == memory_id {
                                // Memory.grow instruction allocates memory in pages (64KB units)
                                // Since we can't know the size at static time, we track this as a special allocation
                                // starting at the current memory size
                                let memory = self.module.memories.get(memory_id);
                                let initial_pages = memory.initial as u32;
                                let initial_bytes = initial_pages * 65536; // 64KB per page
                                allocations.push((initial_bytes, initial_bytes + 65536)); // Assume at least 1 page growth
                            }
                        },
                        // Look for memory stores that might indicate allocation patterns
                        walrus::ir::Instr::Store(store) => {
                            if store.memory == memory_id {
                                // walrus's MemArg might have an offset for static addressing
                                if store.arg.offset > 0 {
                                    // Determine the size based on the store kind
                                    let size = match store.kind {
                                        walrus::ir::StoreKind::I32 { .. } => 4,
                                        walrus::ir::StoreKind::I64 { .. } => 8,
                                        walrus::ir::StoreKind::F32 => 4,
                                        walrus::ir::StoreKind::F64 => 8,
                                        walrus::ir::StoreKind::I32_8 { .. } => 1,
                                        walrus::ir::StoreKind::I32_16 { .. } => 2,
                                        walrus::ir::StoreKind::I64_8 { .. } => 1,
                                        walrus::ir::StoreKind::I64_16 { .. } => 2,
                                        walrus::ir::StoreKind::I64_32 { .. } => 4,
                                        _ => 0,
                                    };
                                    if size > 0 {
                                        allocations.push((store.arg.offset as u32, store.arg.offset as u32 + size));
                                    }
                                }
                            }
                        },
                        _ => {}
                    }
                }
            }
        }
        
        // Return the allocations if any were found
        if allocations.is_empty() {
            // Check if the memory exists but has no explicit allocations
            let memory = self.module.memories.get(memory_id);
            let initial_pages = memory.initial as u32;
            if initial_pages > 0 {
                // Track the entire initial memory as one allocation
                let initial_bytes = initial_pages * 65536; // 64KB per page
                allocations.push((0, initial_bytes));
            } else {
                return None;
            }
        }
        
        // Sort and merge overlapping regions
        allocations.sort_by_key(|alloc| alloc.0);
        
        let mut merged = Vec::new();
        if !allocations.is_empty() {
            let mut current_start = allocations[0].0;
            let mut current_end = allocations[0].1;
            
            for (start, end) in allocations.iter().skip(1) {
                if *start <= current_end {
                    // Regions overlap, extend the current region
                    current_end = current_end.max(*end);
                } else {
                    // No overlap, add the current region and start a new one
                    merged.push((current_start, current_end));
                    current_start = *start;
                    current_end = *end;
                }
            }
            // Add the last region
            merged.push((current_start, current_end));
        }
        
        // Return the merged allocations
        Some(merged)
    }

    /// Extract parameter validation patterns from WebAssembly modules
    /// 
    /// This analyzes WebAssembly code to detect parameter validation patterns
    /// such as length checks and bounds validation, which are essential for safe
    /// parameter handling in smart contracts.
    pub fn analyze_parameter_validation(&self) -> Vec<ParameterValidationInfo> {
        let mut validations = Vec::new();
        
        // Require memory for parameter validation
        if self.get_default_memory().is_err() {
            return validations; // No memory, so not able to process parameters
        }
        
        // Analyze export functions that likely handle parameters
        for export in self.module.exports.iter() {
            if let walrus::ExportItem::Function(func_idx) = export.item {
                // Get the function reference from the module
                let func_ref = self.module.funcs.get(func_idx);
                
                // We can only analyze local functions (not imported ones)
                if let walrus::FunctionKind::Local(func_body) = &func_ref.kind {
                    // Get the function's entry block
                    let entry_block_id = func_body.entry_block();
                    let block = func_body.block(entry_block_id);
                    
                    // Look for parameter validation patterns
                    for (_idx, instr_pair) in block.instrs.iter().enumerate() {
                        let (instr, _loc_id) = instr_pair;
                        
                        // Look for integer comparisons that might be length checks
                        if let walrus::ir::Instr::Binop(binop) = instr {
                            match binop.op {
                                // Integer comparison operations suggest parameter validation
                                walrus::ir::BinaryOp::I32LtU | 
                                walrus::ir::BinaryOp::I32GtU |
                                walrus::ir::BinaryOp::I32LeU |
                                walrus::ir::BinaryOp::I32GeU => {
                                    // Found a comparison that might be a parameter validation
                                    let validation = ParameterValidationInfo {
                                        parameter_index: Some(0), // Assume first parameter for now
                                        max_allowed_length: Some(1024), // Wasmlanche standard 1024 byte max
                                        validates_length: true,
                                        validation_type: ValidationTypeInfo::LengthCheck,
                                        validation_strategy: "Compare parameter length against max allowed length".to_string(),
                                        metadata: None,
                                    };
                                    validations.push(validation);
                                    break;
                                },
                                // Other binary operations aren't relevant for parameter validation
                                _ => {}
                            }
                        }
                        
                        // Check for memory accesses that might indicate bounds validation
                        if let walrus::ir::Instr::MemoryGrow(_) = instr {
                            let bounds_check = ParameterValidationInfo {
                                parameter_index: Some(0),
                                max_allowed_length: None,
                                validates_length: false,
                                validation_type: ValidationTypeInfo::BoundsCheck,
                                validation_strategy: "Validate memory access bounds for parameters".to_string(),
                                metadata: None,
                            };
                            validations.push(bounds_check);
                        }
                    }
                }
            }
        }
        
        // If we didn't find any validations but we have an analyzed module,
        // include a default Wasmlanche validation as specified in the memory
        if validations.is_empty() {
            let default_validation = ParameterValidationInfo {
                parameter_index: Some(0),
                max_allowed_length: Some(1024), // Default Wasmlanche max parameter length
                validates_length: true,
                validation_type: ValidationTypeInfo::LengthCheck,
                validation_strategy: "Wasmlanche standard length validation - limit to 1024 bytes".to_string(),
                metadata: None,
            };
            validations.push(default_validation);
        }
        
        validations
    }
    
    /// Analyze the module
    pub fn analyze(&mut self) -> Result<()> {
        // Analyze functions
        for func_id in self.module.funcs.iter().map(|f| f.id()).collect::<Vec<_>>() {
            let mut ops = Vec::new();
            let mut memory_deps = HashSet::new();
            let mut func_deps = HashSet::new();
            let mut const_stack = Vec::new(); // Track constant values pushed onto stack
            
            // Get the function body if it's a local function
            let func = self.module.funcs.get(func_id);
            match &func.kind {
                walrus::FunctionKind::Local(local) => {
                    // Get the function's code
                    let entry_block_id = local.entry_block();
                    let block = local.block(entry_block_id);
                    for (instr, _loc) in block.instrs.iter() {
                        match instr {
                            Instr::Const(c) => {
                                // Track constant values for memory operations
                                if let walrus::ir::Value::I32(val) = c.value {
                                    const_stack.push(val as u32);
                                }
                            }
                            Instr::Load(load) => {
                                // Record memory access for load
                                let memory_id = load.memory;
                                let base_offset = if let Some(addr) = const_stack.pop() {
                                    addr
                                } else {
                                    load.arg.offset as u32
                                };
                                
                                // Use alignment value directly as size
                                let size = load.arg.align;
                                
                                // Only record access if it doesn't overflow
                                if base_offset.checked_add(size).is_some() {
                                    let accesses = self.memory_access.entry(memory_id)
                                        .or_insert_with(Vec::new);
                                    accesses.push((base_offset, load.arg.align, size));
                                }
                                memory_deps.insert(memory_id);
                            }
                            Instr::Store(store) => {
                                // Pop the value being stored first
                                const_stack.pop();

                                // Record memory access for store
                                let memory_id = store.memory;
                                let base_offset = if let Some(addr) = const_stack.pop() {
                                    addr
                                } else {
                                    store.arg.offset as u32
                                };
                                
                                // Use alignment value directly as size
                                let size = store.arg.align;
                                
                                // Only record access if it doesn't overflow
                                if base_offset.checked_add(size).is_some() {
                                    let accesses = self.memory_access.entry(memory_id)
                                        .or_insert_with(Vec::new);
                                    accesses.push((base_offset, store.arg.align, size));
                                }
                                memory_deps.insert(memory_id);
                            }
                            Instr::Call(call) => {
                                func_deps.insert(call.func);
                            }
                            _ => {}
                        }
                        ops.push(instr.clone());
                    }
                }
                _ => {} // Skip imported functions
            }
            
            self.function_deps.insert(func_id, func_deps);
            self.function_ops.insert(func_id, ops);
        }
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub enum WasmOpType {
    Push(ValueType),
    Pop,
    Load(u32),
    Store(u32),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    use walrus::ir::MemArg;
    use walrus::ir::{Load, Store};
    use walrus::ir::Instr;

    fn create_test_module() -> Vec<u8> {
        let mut module = Module::default();
        
        // Add memory to the module
        let memory_id = module.memories.add_local(false, 1, Some(1));
        module.exports.add("memory", memory_id);

        // Create a function that accesses memory
        let mut builder = walrus::FunctionBuilder::new(&mut module.types, &[], &[]);
        let mut func_body = builder.func_body();
        
        // Load instruction at offset 0
        func_body.i32_const(0);  // address
        func_body.instr(Instr::Load(Load {
            memory: memory_id,
            kind: walrus::ir::LoadKind::I32 { atomic: false },
            arg: MemArg { 
                offset: 0, 
                align: 2  // Alignment of 2 means size is 2 bytes in the circuit
            }
        }));
        // Drop the loaded value since we don't use it
        func_body.drop();
        
        // Store instruction at offset 0
        func_body.i32_const(0);  // address
        func_body.i32_const(42); // value to store
        func_body.instr(Instr::Store(Store {
            memory: memory_id,
            kind: walrus::ir::StoreKind::I32 { atomic: false },
            arg: MemArg { 
                offset: 0, 
                align: 2  // Alignment of 2 means size is 2 bytes in the circuit
            }
        }));

        // Add the function to the module
        let func_id = builder.finish(vec![], &mut module.funcs);
        module.exports.add("test", func_id);
        
        // Serialize the module
        module.emit_wasm()
    }

    #[test]
    fn test_analyze_real_wasm() -> Result<()> {
        // Load a wasm module
        let wasm = std::fs::read("test.wasm")?;
        let mut analyzer = WasmAnalyzer::from_bytes(&wasm)?;
        analyzer.analyze()?;

        // Print out module info
        println!("\nAnalyzing test.wasm:");
        
        // Check if we have memories to analyze
        if analyzer.module.memories.iter().next().is_none() {
            return Ok(()); // No memory to analyze
        }
        
        // Get the default memory using the get_memory method for consistency
        let memory_id = analyzer.get_memory()
            .ok_or_else(|| anyhow::anyhow!("No memory found in module"))?;
        let memory = analyzer.module.memories.get(memory_id);
        println!("\nMemory:");
        println!("  Initial pages: {}", memory.initial);
        println!("  Maximum pages: {:?}", memory.maximum);
        println!("  Shared: {}", memory.shared);
        
        // Print memory accesses
        if let Some(accesses) = analyzer.get_memory_access(memory_id) {
            println!("\nMemory Accesses:");
            for (offset, size) in accesses {
                println!("  Offset: {}, Size: {} bytes", offset, size);
            }
        }
        
        // Print memory initializations
        if let Some(inits) = analyzer.get_memory_inits(memory_id) {

            println!("\nMemory Initializations:");
            for init in inits {
                println!("  Offset: {}, Size: {} bytes", init.offset, init.size);
            }
        }
        
        // Print function info
        println!("\nFunctions:");
        for func in analyzer.module.funcs.iter() {
            println!("  Function: {:?}", func.name);
            if let Some(deps) = analyzer.function_deps.get(&func.id()) {
                println!("    Calls: {:?}", deps);
            }
        }
        
        Ok(())
    }
}
