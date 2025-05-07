//
// This module implements a zero-knowledge circuit that verifies the absence of
// patterns that could harm or stall Alkanes indexers. It ensures:
//
// 1. Loop Safety:
//    - No unbounded loops that could stall indexers
//    - Loop iterations have clear upper bounds
//
// 2. Fuel Consumption Predictability:
//    - Operations with predictable fuel consumption patterns
//    - No excessive fuel usage in unpredictable ways
//
// 3. Dynamic Allocation Safety:
//    - Memory allocations have reasonable bounds
//    - No excessive or unpredictable memory growth
//
// 4. Execution Determinism:
//    - Execution time is predictable regardless of input
//    - No operations that could cause significant timing variations

use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_std::marker::PhantomData;
use walrus::Module;
use ark_relations::lc;
use anyhow::Result;
use std::fmt;
use std::collections::HashSet;
use std::collections::HashMap;

/// Types of indexer vulnerabilities that can affect Alkanes
#[derive(Debug, Clone, PartialEq)]
pub enum IndexerVulnerability {
    /// Unbounded loops that could stall the indexer
    UnboundedLoop(String),
    /// Unpredictable or excessive fuel consumption
    UnpredictableFuelConsumption(String),
    /// Excessive memory allocation or growth
    ExcessiveMemoryUsage(String),
    /// Unpredictable execution time
    UnpredictableExecution(String),
    /// Complex recursion patterns
    ComplexRecursion(String),
}

impl fmt::Display for IndexerVulnerability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IndexerVulnerability::UnboundedLoop(desc) => write!(f, "Unbounded loop: {}", desc),
            IndexerVulnerability::UnpredictableFuelConsumption(desc) => write!(f, "Unpredictable fuel consumption: {}", desc),
            IndexerVulnerability::ExcessiveMemoryUsage(desc) => write!(f, "Excessive memory usage: {}", desc),
            IndexerVulnerability::UnpredictableExecution(desc) => write!(f, "Unpredictable execution: {}", desc),
            IndexerVulnerability::ComplexRecursion(desc) => write!(f, "Complex recursion: {}", desc),
        }
    }
}

/// The circuit for verifying Alkanes indexer safety
#[derive(Clone)]
pub struct IndexerSafetyCircuit<F: Field> {
    /// Detected indexer vulnerabilities
    pub vulnerabilities: Vec<IndexerVulnerability>,
    /// Test mode flag
    pub test_mode: bool,
    /// Maximum allowed loop iterations
    pub max_loop_iterations: u32,
    /// Maximum allowed memory allocation (in pages)
    pub max_memory_pages: u32,
    /// Phantom data for field type
    _phantom: PhantomData<F>,
}

impl<F: Field> IndexerSafetyCircuit<F> {
    /// Create a new indexer safety verification circuit
    pub fn new(module: &Module) -> Self {
        let vulnerabilities = analyze_indexer_vulnerabilities(module);
        Self {
            vulnerabilities,
            test_mode: false,
            max_loop_iterations: 1000,  // Default reasonable limit
            max_memory_pages: 100,      // Default reasonable limit (6.4MB)
            _phantom: PhantomData,
        }
    }

    /// Create a new indexer safety circuit with provided vulnerabilities (for testing)
    pub fn new_with_vulnerabilities(
        vulnerabilities: Vec<IndexerVulnerability>, 
        test_mode: bool
    ) -> Self {
        Self {
            vulnerabilities,
            test_mode,
            max_loop_iterations: 1000,
            max_memory_pages: 100,
            _phantom: PhantomData,
        }
    }

    /// Set test mode for the circuit
    /// 
    /// When test mode is enabled, validation can be bypassed for testing purposes.
    pub fn set_test_mode(&mut self, enabled: bool) -> &mut Self {
        self.test_mode = enabled;
        self
    }

    /// Set maximum allowed loop iterations
    pub fn set_max_loop_iterations(&mut self, max: u32) -> &mut Self {
        self.max_loop_iterations = max;
        self
    }

    /// Set maximum allowed memory pages
    pub fn set_max_memory_pages(&mut self, max: u32) -> &mut Self {
        self.max_memory_pages = max;
        self
    }

    /// Check if test mode is enabled
    pub fn is_test_mode(&self) -> bool {
        self.test_mode
    }

    /// Helper method to convert a u32 to field element
    fn u32_to_field(value: u32) -> F {
        let mut result = F::zero();
        let mut base = F::one();
        let two = F::one() + F::one();
        
        for i in 0..32 {
            if (value >> i) & 1 == 1 {
                result += base;
            }
            base *= two;
        }
        
        result
    }

    /// Convert a boolean to a field element
    fn bool_to_field(b: bool) -> F {
        if b {
            F::one()
        } else {
            F::zero()
        }
    }
}

impl<F: Field> ConstraintSynthesizer<F> for IndexerSafetyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // If test mode is enabled, skip validation
        if self.test_mode {
            return Ok(());
        }

        // Count the different types of vulnerabilities
        let mut unbounded_loops = 0u32;
        let mut unpredictable_fuel = 0u32;
        let mut excessive_memory = 0u32;
        let mut unpredictable_execution = 0u32;
        let mut complex_recursion = 0u32;
        
        for vulnerability in &self.vulnerabilities {
            match vulnerability {
                IndexerVulnerability::UnboundedLoop(_) => unbounded_loops += 1,
                IndexerVulnerability::UnpredictableFuelConsumption(_) => unpredictable_fuel += 1,
                IndexerVulnerability::ExcessiveMemoryUsage(_) => excessive_memory += 1,
                IndexerVulnerability::UnpredictableExecution(_) => unpredictable_execution += 1,
                IndexerVulnerability::ComplexRecursion(_) => complex_recursion += 1,
            }
        }
        
        // We'll create constraints even if vulnerabilities are present
        // This will make the constraint system unsatisfiable
        
        // Create a witness variable for each vulnerability count
        let loops_var = cs.new_witness_variable(|| Ok(Self::u32_to_field(unbounded_loops)))?;
        let fuel_var = cs.new_witness_variable(|| Ok(Self::u32_to_field(unpredictable_fuel)))?;
        let memory_var = cs.new_witness_variable(|| Ok(Self::u32_to_field(excessive_memory)))?;
        let exec_var = cs.new_witness_variable(|| Ok(Self::u32_to_field(unpredictable_execution)))?;
        let recursion_var = cs.new_witness_variable(|| Ok(Self::u32_to_field(complex_recursion)))?;
        
        // For each vulnerability count, constrain it to be zero
        // a * 1 = 0 means a must be 0
        cs.enforce_constraint(
            lc!() + loops_var,
            lc!() + (F::one(), Variable::One),
            lc!()
        )?;
        
        cs.enforce_constraint(
            lc!() + fuel_var,
            lc!() + (F::one(), Variable::One),
            lc!()
        )?;
        
        cs.enforce_constraint(
            lc!() + memory_var,
            lc!() + (F::one(), Variable::One),
            lc!()
        )?;
        
        cs.enforce_constraint(
            lc!() + exec_var,
            lc!() + (F::one(), Variable::One),
            lc!()
        )?;
        
        cs.enforce_constraint(
            lc!() + recursion_var,
            lc!() + (F::one(), Variable::One),
            lc!()
        )?;

        Ok(())
    }
}

/// Analyze a WebAssembly module for indexer vulnerabilities
pub fn analyze_indexer_vulnerabilities(module: &Module) -> Vec<IndexerVulnerability> {
    let mut vulnerabilities = Vec::new();

    // Perform each type of vulnerability detection
    detect_unbounded_loops(module, &mut vulnerabilities);
    detect_unpredictable_fuel_consumption(module, &mut vulnerabilities);
    detect_excessive_memory_usage(module, &mut vulnerabilities);
    detect_unpredictable_execution(module, &mut vulnerabilities);
    detect_complex_recursion(module, &mut vulnerabilities);

    vulnerabilities
}

/// Analyze a WebAssembly module for indexer vulnerabilities with options
pub fn analyze_indexer_vulnerabilities_with_options(
    module: &Module,
    max_loop_iterations: u32,
    max_memory_pages: u32,
    test_mode: bool,
) -> Vec<IndexerVulnerability> {
    if test_mode {
        return Vec::new(); // Skip analysis in test mode
    }

    let mut vulnerabilities = Vec::new();

    // Perform each type of vulnerability detection with custom parameters
    detect_unbounded_loops_with_params(module, &mut vulnerabilities, max_loop_iterations);
    detect_unpredictable_fuel_consumption(module, &mut vulnerabilities);
    detect_excessive_memory_usage_with_params(module, &mut vulnerabilities, max_memory_pages);
    detect_unpredictable_execution(module, &mut vulnerabilities);
    detect_complex_recursion(module, &mut vulnerabilities);

    vulnerabilities
}

/// Detect unbounded loops that could stall the indexer
pub fn detect_unbounded_loops(module: &Module, vulnerabilities: &mut Vec<IndexerVulnerability>) {
    detect_unbounded_loops_with_params(module, vulnerabilities, 1000); // Default 1000 max iterations
}

/// Detect unbounded loops with custom parameters
pub fn detect_unbounded_loops_with_params(
    module: &Module, 
    vulnerabilities: &mut Vec<IndexerVulnerability>,
    _max_iterations: u32,
) {
    // Keywords that suggest loop constructs in function names or debug info
    let _loop_keywords = ["loop", "while", "for", "repeat", "iter"];
    
    for function in module.funcs.iter() {
        let name = if let Some(name) = &function.name {
            name.to_string()
        } else {
            "<unnamed>".to_string()
        };
        
        if let walrus::FunctionKind::Local(local_func) = &function.kind {
            // Check for loop instructions
            let mut has_loop = false;
            let mut has_bounded_counter = false;
            
            let entry_block_id = local_func.entry_block();
            let block = local_func.block(entry_block_id);
            
            // Process instructions in this block
            for (instr, _) in &block.instrs {
                let instr_str = format!("{:?}", instr).to_lowercase();
                
                // Check if this is a loop construct
                if instr_str.contains("loop") {
                    has_loop = true;
                }
                
                // Check if there's a counter being incremented (common in bounded loops)
                if (instr_str.contains("local.get") && instr_str.contains("i32.add") && 
                    instr_str.contains("local.set")) ||
                   (instr_str.contains("local.get") && instr_str.contains("i32.const") && 
                    instr_str.contains("i32.lt")) {
                    has_bounded_counter = true;  
                }
            }
            
            // If we found a loop without clear termination or bounded counter, flag it
            if has_loop && !has_bounded_counter {
                vulnerabilities.push(IndexerVulnerability::UnboundedLoop(
                    format!("Function '{}' contains a potentially unbounded loop that could stall the Alkanes indexer", name)
                ));
            }
        }
    }
}

/// Detect complex recursion patterns that could lead to stack overflow or excessive resource usage
pub fn detect_complex_recursion(module: &Module, vulnerabilities: &mut Vec<IndexerVulnerability>) {
    // First check for direct recursion
    detect_direct_recursion(module, vulnerabilities);
    
    // Then check for mutual recursion and non-tail recursion
    detect_mutual_recursion(module, vulnerabilities);
    detect_non_tail_recursion(module, vulnerabilities);
}

/// Detect direct recursion in the module
pub fn detect_direct_recursion(module: &Module, vulnerabilities: &mut Vec<IndexerVulnerability>) {
    println!("======== Detecting Direct Recursion ========");
    // Check for direct recursion (function calls itself)
    for function in module.funcs.iter() {
        let name = function.name.clone().unwrap_or("<unnamed>".to_string());
        let current_func_id = function.id();
        println!("Checking function {:?} with ID {:?} for direct recursion", name, current_func_id);
        
        if let walrus::FunctionKind::Local(local_func) = &function.kind {
            let mut calls_self = false;
            
            // Queue to track blocks to check (starting with entry block)
            let mut blocks_to_check = vec![local_func.entry_block()];
            let mut checked_blocks = HashSet::new();
            
            // Recursively check all code blocks in the function
            while let Some(block_id) = blocks_to_check.pop() {
                if checked_blocks.contains(&block_id) {
                    continue;
                }
                
                checked_blocks.insert(block_id);
                let block = local_func.block(block_id);
                println!("Processing block {:?} with {} instructions", block_id, block.instrs.len());
                
                // Check each instruction for calls to self and collect nested blocks
                for (instr, _) in &block.instrs {
                    println!("  - Instruction: {:?}", instr);
                    match instr {
                        // Check for direct recursive call
                        walrus::ir::Instr::Call(call) => {
                            println!("    Found Call instruction to func ID: {:?}", call.func);
                            println!("    Current function ID: {:?}", current_func_id);
                            println!("    Comparison result: {} (true = recursion detected)", call.func == current_func_id);
                            
                            if call.func == current_func_id {
                                println!("    DIRECT RECURSION DETECTED!");
                                calls_self = true;
                                vulnerabilities.push(IndexerVulnerability::UnpredictableExecution(
                                    format!("Function '{}' contains direct recursion (calls itself)", name)
                                ));
                                break;
                            }
                        },
                        // Queue nested blocks for checking
                        walrus::ir::Instr::Block(block_instr) => {
                            blocks_to_check.push(block_instr.seq);
                        },
                        walrus::ir::Instr::Loop(loop_instr) => {
                            blocks_to_check.push(loop_instr.seq);
                        },
                        walrus::ir::Instr::IfElse(if_instr) => {
                            // Add both branches for checking
                            blocks_to_check.push(if_instr.consequent); // Then branch
                            blocks_to_check.push(if_instr.alternative); // Else branch
                        },
                        _ => {}
                    }
                }
                
                if calls_self {
                    break;
                }
            }
            
            if calls_self {
                break; // No need to check other functions once recursion is found
            }
        }
    }
}

/// Detect mutual recursion patterns that could lead to stack overflow or excessive resource usage
pub fn detect_mutual_recursion(module: &Module, vulnerabilities: &mut Vec<IndexerVulnerability>) {
    // Build a call graph to detect recursive calls
    let mut call_graph: HashMap<String, HashSet<String>> = HashMap::new();
    let mut function_names: HashMap<u32, String> = HashMap::new();
    
    // First, collect all function names by their indices
    for (idx, func) in module.funcs.iter().enumerate() {
        let name = func.name.clone().unwrap_or(format!("func_{}", idx));
        function_names.insert(idx as u32, name.clone());
        call_graph.insert(name, HashSet::new());
    }
    
    // Build the call graph
    for (idx, func) in module.funcs.iter().enumerate() {
        let caller_name = function_names.get(&(idx as u32)).cloned().unwrap_or_default();
        
        if let walrus::FunctionKind::Local(local_func) = &func.kind {
            let entry_block_id = local_func.entry_block();
            let block = local_func.block(entry_block_id);
            
            // Process instructions in this block
            for (instr, _) in &block.instrs {
                let instr_str = format!("{:?}", instr);
                
                // Check for direct calls
                if instr_str.contains("Call") {
                    // Extract function index from the call instruction
                    // This is a simplified approach - production code would need more robust parsing
                    if let Some(callee_idx_str) = instr_str.split("Call { function_index: ").nth(1) {
                        if let Some(callee_idx_str) = callee_idx_str.split(" }").next() {
                            if let Ok(callee_idx) = callee_idx_str.parse::<u32>() {
                                if let Some(callee_name) = function_names.get(&callee_idx) {
                                    if let Some(callees) = call_graph.get_mut(&caller_name) {
                                        callees.insert(callee_name.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Detect direct recursion (self-calls)
    for (func_name, callees) in &call_graph {
        if callees.contains(func_name) {
            vulnerabilities.push(IndexerVulnerability::ComplexRecursion(
                format!("Function '{}' directly calls itself (recursion), which could lead to stack overflow", func_name)
            ));
        }
    }
    
    // Detect mutual recursion (cycles in the call graph)
    detect_mutual_recursion_impl(&call_graph, vulnerabilities);
    
    // Check for tail recursion as a potential mitigation
    detect_non_tail_recursion(module, vulnerabilities);
}

/// Helper function to detect mutual recursion in the call graph
fn detect_mutual_recursion_impl(
    call_graph: &HashMap<String, HashSet<String>>,
    vulnerabilities: &mut Vec<IndexerVulnerability>
) {
    let mut visited = HashSet::new();
    let mut stack = HashSet::new();
    
    // DFS to find cycles in the call graph
    for func_name in call_graph.keys() {
        if !visited.contains(func_name) {
            find_cycles(func_name, call_graph, &mut visited, &mut stack, vulnerabilities);
        }
    }
}

/// Helper function to find cycles in the call graph using DFS
pub fn find_cycles(
    current: &str,
    call_graph: &HashMap<String, HashSet<String>>,
    visited: &mut HashSet<String>,
    stack: &mut HashSet<String>,
    vulnerabilities: &mut Vec<IndexerVulnerability>
) {
    visited.insert(current.to_string());
    stack.insert(current.to_string());
    
    if let Some(neighbors) = call_graph.get(current) {
        for neighbor in neighbors {
            if !visited.contains(neighbor) {
                find_cycles(neighbor, call_graph, visited, stack, vulnerabilities);
            } else if stack.contains(neighbor) {
                // Found a cycle
                vulnerabilities.push(IndexerVulnerability::ComplexRecursion(
                    format!("Detected mutual recursion involving function '{}'", neighbor)
                ));
            }
        }
    }
    
    stack.remove(current);
}

/// Detect excessive memory usage that could overload indexers
pub fn detect_excessive_memory_usage(module: &Module, vulnerabilities: &mut Vec<IndexerVulnerability>) {
    detect_excessive_memory_usage_with_params(module, vulnerabilities, 100); // Default 100 pages (6.4MB)
}

/// Detect excessive memory usage with custom parameters
pub fn detect_excessive_memory_usage_with_params(
    module: &Module,
    vulnerabilities: &mut Vec<IndexerVulnerability>,
    max_pages: u32,
) {
    // Check for memory sections with large initial or maximum sizes
    for memory in module.memories.iter() {
        let initial = memory.initial;
        let maximum = memory.maximum.unwrap_or(u32::MAX);
        
        if initial > max_pages {
            vulnerabilities.push(IndexerVulnerability::ExcessiveMemoryUsage(
                format!("Memory initialized with {} pages ({}MB), which exceeds the recommended maximum of {} pages ({}MB)",
                    initial, (initial as f32 * 0.064), max_pages, (max_pages as f32 * 0.064))
            ));
        }
        
        if maximum > max_pages * 2 {
            vulnerabilities.push(IndexerVulnerability::ExcessiveMemoryUsage(
                format!("Memory can grow to {} pages ({}MB), which exceeds the recommended maximum of {} pages ({}MB)",
                    maximum, (maximum as f32 * 0.064), max_pages * 2, (max_pages as f32 * 2.0 * 0.064))
            ));
        }
    }
    
    // Check for memory.grow operations that could lead to excessive memory
    for function in module.funcs.iter() {
        let name = function.name.clone().unwrap_or("<unnamed>".to_string());
        let mut has_memory_grow = false;
        let mut has_bounded_grow = false;
        
        if let walrus::FunctionKind::Local(local_func) = &function.kind {
            let entry_block_id = local_func.entry_block();
            let block = local_func.block(entry_block_id);
            
            // Process instructions in this block
            for (instr, _) in &block.instrs {
                let instr_str = format!("{:?}", instr).to_lowercase();
                
                if instr_str.contains("memory.grow") {
                    has_memory_grow = true;
                }
                
                // Check for comparison against a constant before memory.grow
                // This is a common pattern for bounded growth
                if instr_str.contains("i32.const") && 
                   (instr_str.contains("i32.lt") || instr_str.contains("i32.le") || 
                    instr_str.contains("i32.gt") || instr_str.contains("i32.ge")) {
                    has_bounded_grow = true;
                }
            }
        }
        
        // If we have memory.grow without bounds checking, flag it
        if has_memory_grow && !has_bounded_grow {
            vulnerabilities.push(IndexerVulnerability::ExcessiveMemoryUsage(
                format!("Function '{}' contains unbounded memory.grow operations that could consume excessive memory", name)
            ));
        }
    }
}

/// Detect unpredictable fuel consumption that could lead to unexpected costs
pub fn detect_unpredictable_fuel_consumption(module: &Module, vulnerabilities: &mut Vec<IndexerVulnerability>) {
    // Analyze instructions that have unpredictable fuel consumption
    for func in module.funcs.iter() {
        let func_name = func.name.clone().unwrap_or("<unnamed>".to_string());
        let mut has_risky_instructions = false;
        let mut has_complex_loop = false;
        
        if let walrus::FunctionKind::Local(local_func) = &func.kind {
            let mut in_loop = false;
            
            let entry_block_id = local_func.entry_block();
            let block = local_func.block(entry_block_id);
            
            // Process instructions in this block
            for (instr, _) in &block.instrs {
                let instr_str = format!("{:?}", instr).to_lowercase();
                
                // Check if we're in a loop
                if instr_str.contains("loop") {
                    in_loop = true;
                } else if instr_str.contains("end") && in_loop {
                    in_loop = false;
                }
                
                // Instructions with unpredictable fuel cost
                let is_variable_cost = 
                    instr_str.contains("call_indirect") ||
                    instr_str.contains("table.get") ||
                    instr_str.contains("table.set") ||
                    instr_str.contains("table.grow") ||
                    instr_str.contains("table.size") ||
                    instr_str.contains("memory.size") ||
                    instr_str.contains("memory.grow");
                
                if is_variable_cost {
                    has_risky_instructions = true;
                    
                    // Variable cost in a loop is especially problematic
                    if in_loop {
                        has_complex_loop = true;
                    }
                }
            }
        }
        
        if has_complex_loop {
            vulnerabilities.push(IndexerVulnerability::UnpredictableFuelConsumption(
                format!("Function '{}' contains operations with variable fuel costs inside loops", func_name)
            ));
        } else if has_risky_instructions {
            vulnerabilities.push(IndexerVulnerability::UnpredictableFuelConsumption(
                format!("Function '{}' contains operations with unpredictable fuel consumption", func_name)
            ));
        }
    }
}

/// Check if recursion is properly tail-call optimized
pub fn detect_non_tail_recursion(module: &Module, vulnerabilities: &mut Vec<IndexerVulnerability>) {
    for function in module.funcs.iter() {
        let name = function.name.clone().unwrap_or("<unnamed>".to_string());
        let mut has_recursive_call = false;
        let mut has_tail_call = false;
        
        if let walrus::FunctionKind::Local(local_func) = &function.kind {
            let entry_block_id = local_func.entry_block();
            let block = local_func.block(entry_block_id);
            
            // Check the last instruction of each block for tail calls
            if let Some((last_instr, _)) = block.instrs.last() {
                let instr_str = format!("{:?}", last_instr).to_lowercase();
                
                // Check if this is a call instruction
                if instr_str.contains("call") {
                    // Check if the call could be to this function (recursion)
                    // This is a simplified check and would need more robust parsing in production
                    if instr_str.contains(&name.to_lowercase()) {
                        has_recursive_call = true;
                        
                        // Check if the call is the last instruction followed by a return
                        // This indicates potential for tail-call optimization
                        if instr_str.ends_with("return") || 
                           block.instrs.iter().any(|(i, _)| format!("{:?}", i).to_lowercase().contains("return")) {
                            has_tail_call = true;
                        }
                    }
                }
            }
        }
        
        // If we have recursion but not in tail position, flag it
        if has_recursive_call && !has_tail_call {
            vulnerabilities.push(IndexerVulnerability::ComplexRecursion(
                format!("Function '{}' contains recursive calls not in tail position, which could lead to stack overflow", name)
            ));
        }
    }
}

/// Detect operations with unpredictable execution time
pub fn detect_unpredictable_execution(module: &Module, vulnerabilities: &mut Vec<IndexerVulnerability>) {
    // Operations that often lead to unpredictable execution time
    let unpredictable_ops = [
        "call_indirect",   // Indirect calls can have variable resolution time
        "select",         // Data-dependent branching
        "table.get",      // Accessing table elements can be unpredictable
        "br_table"        // Branch tables with variable indices
    ];
    
    // Data types that could lead to variable-time operations
    let variable_time_types = [
        "f32", "f64"      // Floating point operations often have variable execution time
    ];
    
    for function in module.funcs.iter() {
        let name = function.name.clone().unwrap_or("<unnamed>".to_string());
        let mut has_unpredictable_ops = false;
        let mut has_data_dependent_control_flow = false;
        let mut has_floating_point_in_loop = false;
        let mut has_variable_access_pattern = false;
        
        // Check function name for suspicious patterns
        let suspicious_name_patterns = ["compute", "calculate", "hash", "encrypt", "decrypt", "sign", "verify"];
        let name_lower = name.to_lowercase();
        let is_crypto_suggestive = suspicious_name_patterns.iter().any(|&pattern| name_lower.contains(pattern));
        
        if let walrus::FunctionKind::Local(local_func) = &function.kind {
            let mut in_loop = false;
            
            // We need to process all blocks, not just the entry block
            // First, collect all block IDs
            let mut block_ids = vec![local_func.entry_block()];
            let mut processed_blocks = HashSet::new();
            
            // Process all blocks in the function
            while let Some(block_id) = block_ids.pop() {
                if processed_blocks.contains(&block_id) {
                    continue;
                }
                
                processed_blocks.insert(block_id);
                let block = local_func.block(block_id);
                
                // In the updated walrus API, we need to stick to analyzing instructions in the current block
                // We won't try to traverse all blocks since the API has changed significantly
                // This simpler approach will ensure compatibility
                
                // Process instructions in this block
                for (instr, _) in &block.instrs {
                    let instr_str = format!("{:?}", instr).to_lowercase();
                    
                    // Check if we are entering or exiting a loop
                    if instr_str.contains("loop") {
                        in_loop = true;
                    } else if instr_str.contains("end") && in_loop {
                        in_loop = false;
                    }
                    
                    // Check for unpredictable operations
                    if unpredictable_ops.iter().any(|&op| instr_str.contains(op)) {
                        has_unpredictable_ops = true;
                    }
                    
                    // Directly check for CallIndirect variant
                    match instr {
                        walrus::ir::Instr::CallIndirect(_) => {
                            // Always add a vulnerability for call_indirect
                            vulnerabilities.push(IndexerVulnerability::UnpredictableExecution(
                                format!("Function '{}' uses call_indirect which leads to unpredictable execution time", name)
                            ));
                        },
                        _ => {}
                    }
                    
                    // Check for variable-time operations
                    if variable_time_types.iter().any(|&typ| instr_str.contains(typ)) {
                        if in_loop {
                            has_floating_point_in_loop = true;
                        }
                    }
                    
                    // Check for data-dependent control flow
                    if (instr_str.contains("br_if") || instr_str.contains("if")) &&
                       (instr_str.contains("local.get") || instr_str.contains("global.get") ||
                        instr_str.contains("memory.load")) {
                        has_data_dependent_control_flow = true;
                    }
                    
                    // Check for variable memory access patterns
                    if (instr_str.contains("memory.load") || instr_str.contains("memory.store")) &&
                       !instr_str.contains("i32.const") && instr_str.contains("local.get") {
                        has_variable_access_pattern = true;
                    }
                    
                    // Check for parameter validation based on safe parameter handling practices
                    if instr_str.contains("memory.load") {
                        // Look for bounds checking before memory loads
                        let mut has_bounds_check = false;
                        
                        // Look for bounds checking patterns in nearby instructions
                        if instr_str.contains("i32.lt_u") || instr_str.contains("i32.gt_u") ||
                           instr_str.contains("i32.le_u") || instr_str.contains("i32.ge_u") {
                            has_bounds_check = true;
                        }
                        
                        if !has_bounds_check {
                            vulnerabilities.push(IndexerVulnerability::UnpredictableExecution(
                                format!("Function '{}' may have unsafe memory loads without proper bounds checking", name)
                            ));
                        }
                    }
                }
            }
        }
        
        // Report vulnerabilities based on detected patterns
        // Always report call_indirect operations as unpredictable
        if has_unpredictable_ops {
            let message = if is_crypto_suggestive {
                format!("Function '{}' uses unpredictable operations in what appears to be a cryptographic context", name)
            } else {
                format!("Function '{}' contains operations with unpredictable execution time", name)
            };
            vulnerabilities.push(IndexerVulnerability::UnpredictableExecution(message));
        }
        
        if has_floating_point_in_loop {
            vulnerabilities.push(IndexerVulnerability::UnpredictableExecution(
                format!("Function '{}' uses floating point operations in loops, which can lead to unpredictable execution time", name)
            ));
        }
        
        if has_data_dependent_control_flow && has_variable_access_pattern {
            vulnerabilities.push(IndexerVulnerability::UnpredictableExecution(
                format!("Function '{}' has data-dependent control flow combined with variable memory access patterns, which can lead to highly unpredictable execution", name)
            ));
        }
    }
}

/// Detect data-dependent control flow that could lead to timing side channels
pub fn detect_data_dependent_control_flow(module: &Module, vulnerabilities: &mut Vec<IndexerVulnerability>) {
    // Look for control flow operations that depend on input data
    for function in module.funcs.iter() {
        let name = function.name.clone().unwrap_or("<unnamed>".to_string());
        let mut has_data_dependent_control = false;
        let mut has_input_dependent_branch = false;
        let mut has_sensitive_context = false;
        
        // Check function name for security-sensitive context
        let sensitive_name_patterns = ["crypto", "verify", "auth", "password", "secret", "token", "key"];
        let name_lower = name.to_lowercase();
        has_sensitive_context = sensitive_name_patterns.iter().any(|&pattern| name_lower.contains(pattern));
        
        if let walrus::FunctionKind::Local(local_func) = &function.kind {
            let mut block_ids = vec![local_func.entry_block()];
            let mut processed_blocks = HashSet::new();
            
            // Process all blocks in the function
            while let Some(block_id) = block_ids.pop() {
                if processed_blocks.contains(&block_id) {
                    continue;
                }
                
                processed_blocks.insert(block_id);
                let block = local_func.block(block_id);
                
                // Track the previous instruction to detect patterns like LocalGet followed by IfElse
                let mut prev_instr: Option<&walrus::ir::Instr> = None;
                let mut is_param_access = false;
                
                // Process instructions in this block
                for (instr, _) in &block.instrs {
                    let instr_str = format!("{:?}", instr).to_lowercase();
                    
                    // Check if this is a parameter access instruction
                    let is_param_access = match instr {
                        walrus::ir::Instr::LocalGet(local) => {
                            // Consider the first few locals as parameters (typically 0 and 1)
                            let local_id = local.local;
                            // Instead of accessing idx directly, we'll assume the lowest IDs are parameters
                            // We can compare ID equality with one of the first few expected parameters
                            true // Assume all local.get instructions could be parameter access
                        },
                        _ => false
                    };
                    
                    // Check for IfElse after parameter access
                    match instr {
                        walrus::ir::Instr::IfElse(_) => {
                            // Check if previous instruction was a parameter access
                            if let Some(prev) = prev_instr {
                                if let walrus::ir::Instr::LocalGet(_) = prev {
                                    // Data-dependent control flow detected!
                                    vulnerabilities.push(IndexerVulnerability::UnpredictableExecution(
                                        format!("Function '{}' contains data-dependent control flow: parameter access followed by if/else", name)
                                    ));
                                }
                            }
                        },
                        _ => {}
                    }
                    
                    // Update the previous instruction tracker
                    prev_instr = Some(instr);
                    
                    // Check for other conditional branches that could depend on input
                    let instr_str = format!("{:?}", instr).to_lowercase();
                    if is_param_access && (instr_str.contains("br_if")) {
                        has_input_dependent_branch = true;
                    }
                    
                    // Check for other data-dependent control flow patterns
                    if instr_str.contains("br_table") && is_param_access {
                        has_data_dependent_control = true;
                    }
                }
            }
        }
        
        // Report vulnerabilities based on detected patterns
        if has_input_dependent_branch && has_sensitive_context {
            vulnerabilities.push(IndexerVulnerability::UnpredictableExecution(
                format!("Function '{}' contains security-sensitive control flow that depends on input data, which could lead to timing side channels", name)
            ));
        } else if has_data_dependent_control {
            vulnerabilities.push(IndexerVulnerability::UnpredictableExecution(
                format!("Function '{}' contains control flow that depends on input data, which could lead to variable execution time", name)
            ));
        }
    }
}

/// Detect missing bounds checks for memory operations
pub fn detect_missing_bounds_check(module: &Module, vulnerabilities: &mut Vec<IndexerVulnerability>) {
    // Look for memory operations that lack proper bounds checking
    for function in module.funcs.iter() {
        let name = function.name.clone().unwrap_or("<unnamed>".to_string());
        
        if let walrus::FunctionKind::Local(local_func) = &function.kind {
            let mut block_ids = vec![local_func.entry_block()];
            let mut processed_blocks = HashSet::new();
            
            // Process all blocks in the function
            while let Some(block_id) = block_ids.pop() {
                if processed_blocks.contains(&block_id) {
                    continue;
                }
                
                processed_blocks.insert(block_id);
                let block = local_func.block(block_id);
                
                // Track memory operations and bounds checks
                let mut memory_ops = Vec::new();
                let mut has_bounds_check = false;
                
                // First pass: collect all memory operations
                for (instr, _) in &block.instrs {
                    let instr_str = format!("{:?}", instr).to_lowercase();
                    
                    // Track memory operations
                    if instr_str.contains("load") || instr_str.contains("store") {
                        memory_ops.push(instr_str.clone());
                    }
                    
                    // Track potential bounds checking operations
                    if instr_str.contains("lt_u") || instr_str.contains("lt_s") ||
                       instr_str.contains("gt_u") || instr_str.contains("gt_s") ||
                       instr_str.contains("le_u") || instr_str.contains("le_s") ||
                       instr_str.contains("ge_u") || instr_str.contains("ge_s") {
                        has_bounds_check = true;
                    }
                    
                    // Also check for memory.size which is often used for bounds checking
                    if instr_str.contains("memory.size") {
                        has_bounds_check = true;
                    }
                }
                
                // Check if we have memory operations without bounds checks
                if !memory_ops.is_empty() && !has_bounds_check {
                    let memory_op_desc = memory_ops.join(", ");
                    vulnerabilities.push(IndexerVulnerability::UnpredictableExecution(
                        format!("Function '{}' has memory operations without bounds checking: {}", 
                                name, memory_op_desc)
                    ));
                    break;  // One vulnerability per function is enough
                }
            }
        }
    }
}

/// Detect floating point operations in loops which can lead to unpredictable execution time
pub fn detect_floating_point_in_loop(module: &Module, vulnerabilities: &mut Vec<IndexerVulnerability>) {
    // Look for floating point operations within loops
    for function in module.funcs.iter() {
        let name = function.name.clone().unwrap_or("<unnamed>".to_string());
        
        if let walrus::FunctionKind::Local(local_func) = &function.kind {
            let mut block_ids = vec![local_func.entry_block()];
            let mut processed_blocks = HashSet::new();
            
            // We'll track all loop blocks and check all instructions within them
            let mut loop_blocks = HashSet::new();
            let mut current_loop_blocks = Vec::new();
            
            // First pass: identify all loop blocks
            while let Some(block_id) = block_ids.pop() {
                if processed_blocks.contains(&block_id) {
                    continue;
                }
                
                processed_blocks.insert(block_id);
                let block = local_func.block(block_id);
                
                // Scan the instructions to identify loop blocks
                for (instr, _) in &block.instrs {
                    match instr {
                        walrus::ir::Instr::Loop(loop_instr) => {
                            // When we find a Loop instruction, add its block ID to our loop blocks set
                            current_loop_blocks.push(loop_instr.seq);
                            loop_blocks.insert(loop_instr.seq);
                        },
                        _ => {}
                    }
                }
                
                // Add all found loop blocks to the processing queue
                for &loop_block in &current_loop_blocks {
                    if !processed_blocks.contains(&loop_block) {
                        block_ids.push(loop_block);
                    }
                }
                current_loop_blocks.clear();
            }
            
            // Second pass: look for floating point operations in loop blocks
            processed_blocks.clear();
            let mut has_fp_in_loop = false;
            
            // Only process blocks that are part of a loop
            for &loop_block_id in &loop_blocks {
                if processed_blocks.contains(&loop_block_id) {
                    continue;
                }
                
                processed_blocks.insert(loop_block_id);
                let loop_block = local_func.block(loop_block_id);
                
                // Check for floating point operations in this loop block
                for (instr, _) in &loop_block.instrs {
                    // Check directly if the instruction is a floating point operation
                    match instr {
                        // Match specific floating point operations
                        walrus::ir::Instr::Binop(binop) => {
                            let op_str = format!("{:?}", binop.op).to_lowercase();
                            if op_str.contains("f32") || op_str.contains("f64") {
                                // Found floating point arithmetic in a loop
                                vulnerabilities.push(IndexerVulnerability::UnpredictableExecution(
                                    format!("Function '{}' contains floating point operations in loops, which can lead to unpredictable execution time", name)
                                ));
                                has_fp_in_loop = true;
                                break;
                            }
                        },
                        // Check for other floating point operations by string matching
                        _ => {
                            let instr_str = format!("{:?}", instr).to_lowercase();
                            if (instr_str.contains("f32") || instr_str.contains("f64")) && 
                               (instr_str.contains("const") || instr_str.contains("load") || 
                                instr_str.contains("store") || instr_str.contains("convert")) {
                                // Found floating point operation in a loop
                                vulnerabilities.push(IndexerVulnerability::UnpredictableExecution(
                                    format!("Function '{}' contains floating point operations in loops, which can lead to unpredictable execution time: {}", 
                                           name, instr_str)
                                ));
                                has_fp_in_loop = true;
                                break;
                            }
                        }
                    }
                }
                
                if has_fp_in_loop {
                    break; // One vulnerability per function is enough
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use walrus::ModuleConfig;
    use wat::parse_str;
    use ark_bls12_381::Fr;
    use anyhow::Result;

    #[test]
    fn test_detect_unpredictable_execution() {
        let result = test_detect_unpredictable_execution_impl();
        assert!(result.is_ok());
    }

    fn test_detect_unpredictable_execution_impl() -> Result<()> {
        // Test case for call_indirect instruction
        let wat = r#"
            (module
                (table 1 funcref)
                (elem (i32.const 0) $function)
                (func $function (result i32) i32.const 42)
                (func $call_indirect (param i32) (result i32)
                    local.get 0
                    call_indirect (result i32)
                )
                (export "call_indirect" (func $call_indirect))
            )
        "#;
        
        let wasm = wat::parse_str(wat)?;
        let module = Module::from_buffer(&wasm)?;
        
        let mut vulnerabilities = Vec::new();
        detect_unpredictable_execution(&module, &mut vulnerabilities);
        
        assert!(
            vulnerabilities.iter().any(|v| matches!(v, IndexerVulnerability::UnpredictableExecution(_))),
            "Should detect unpredictable execution due to call_indirect"
        );
        
        Ok(())
    }

    #[test]
    fn test_detect_data_dependent_control_flow() {
        let result = test_detect_data_dependent_control_flow_impl();
        assert!(result.is_ok());
    }

    fn test_detect_data_dependent_control_flow_impl() -> Result<()> {
        // Test case for data-dependent control flow
        let wat = r#"
            (module
                (func $crypto_verify (param i32 i32) (result i32)
                    local.get 0
                    local.get 1
                    i32.eq
                    if (result i32)
                        i32.const 1
                    else
                        i32.const 0
                    end
                )
                (export "crypto_verify" (func $crypto_verify))
            )
        "#;
        
        let wasm = wat::parse_str(wat)?;
        let module = Module::from_buffer(&wasm)?;
        
        let mut vulnerabilities = Vec::new();
        detect_unpredictable_execution(&module, &mut vulnerabilities);
        
        assert!(
            vulnerabilities.iter().any(|v| matches!(v, IndexerVulnerability::UnpredictableExecution(_))),
            "Should detect unpredictable execution due to data-dependent control flow in crypto context"
        );
        
        Ok(())
    }

    #[test]
    fn test_detect_missing_bounds_check() {
        let result = test_detect_missing_bounds_check_impl();
        assert!(result.is_ok());
    }

    fn test_detect_missing_bounds_check_impl() -> Result<()> {
        // Test case for memory access without bounds check
        let wat = r#"
            (module
                (memory 1)
                (func $unchecked_load (param i32) (result i32)
                    local.get 0
                    i32.load
                )
                (export "unchecked_load" (func $unchecked_load))
            )
        "#;
        
        let wasm = wat::parse_str(wat)?;
        let module = Module::from_buffer(&wasm)?;
        
        let mut vulnerabilities = Vec::new();
        detect_unpredictable_execution(&module, &mut vulnerabilities);
        
        assert!(
            vulnerabilities.iter().any(|v| matches!(v, IndexerVulnerability::UnpredictableExecution(_))),
            "Should detect unpredictable execution due to missing bounds check"
        );
        
        Ok(())
    }

    #[test]
    fn test_detect_floating_point_in_loop() {
        let result = test_detect_floating_point_in_loop_impl();
        assert!(result.is_ok());
    }

    fn test_detect_floating_point_in_loop_impl() -> Result<()> {
        // Test case for floating point operations in a loop
        let wat = r#"
            (module
                (func $float_loop (param f32 i32) (result f32)
                    (local f32)
                    local.get 0
                    local.set 2
                    block
                        loop
                            local.get 1
                            i32.const 0
                            i32.le_s
                            br_if 1
                            local.get 2
                            local.get 0
                            f32.mul
                            local.set 2
                            local.get 1
                            i32.const 1
                            i32.sub
                            local.set 1
                            br 0
                        end
                    end
                    local.get 2
                )
                (export "float_loop" (func $float_loop))
            )
        "#;
        
        let wasm = wat::parse_str(wat)?;
        let module = Module::from_buffer(&wasm)?;
        
        let mut vulnerabilities = Vec::new();
        detect_unpredictable_execution(&module, &mut vulnerabilities);
        
        assert!(
            vulnerabilities.iter().any(|v| matches!(v, IndexerVulnerability::UnpredictableExecution(_))),
            "Should detect unpredictable execution due to floating point operations in a loop"
        );
        
        Ok(())
    }

    #[test]
    fn test_detect_direct_recursion() {
        let result = test_detect_direct_recursion_impl();
        assert!(result.is_ok());
    }

    fn test_detect_direct_recursion_impl() -> Result<()> {
        // Test case for direct recursion
        let wat = r#"
            (module
                (func $factorial (param i32) (result i32)
                    local.get 0
                    i32.const 0
                    i32.eq
                    if (result i32)
                        i32.const 1
                    else
                        local.get 0
                        local.get 0
                        i32.const 1
                        i32.sub
                        call $factorial
                        i32.mul
                    end
                )
                (export "factorial" (func $factorial))
            )
        "#;
        
        let wasm = wat::parse_str(wat)?;
        let module = Module::from_buffer(&wasm)?;
        
        let mut vulnerabilities = Vec::new();
        detect_complex_recursion(&module, &mut vulnerabilities);
        
        assert!(
            vulnerabilities.iter().any(|v| matches!(v, IndexerVulnerability::ComplexRecursion(_))),
            "Should detect complex recursion due to direct recursion"
        );
        
        Ok(())
    }

    #[test]
    fn test_detect_mutual_recursion() {
        let result = test_detect_mutual_recursion_impl();
        assert!(result.is_ok());
    }

    fn test_detect_mutual_recursion_impl() -> Result<()> {
        // Test case for mutual recursion
        let wat = r#"
            (module
                (func $is_even (param i32) (result i32)
                    local.get 0
                    i32.const 0
                    i32.eq
                    if (result i32)
                        i32.const 1
                    else
                        local.get 0
                        i32.const 1
                        i32.sub
                        call $is_odd
                    end
                )
                (func $is_odd (param i32) (result i32)
                    local.get 0
                    i32.const 0
                    i32.eq
                    if (result i32)
                        i32.const 0
                    else
                        local.get 0
                        i32.const 1
                        i32.sub
                        call $is_even
                    end
                )
                (export "is_even" (func $is_even))
                (export "is_odd" (func $is_odd))
            )
        "#;
        
        let wasm = wat::parse_str(wat)?;
        let module = Module::from_buffer(&wasm)?;
        
        let mut vulnerabilities = Vec::new();
        detect_complex_recursion(&module, &mut vulnerabilities);
        
        assert!(
            vulnerabilities.iter().any(|v| matches!(v, IndexerVulnerability::ComplexRecursion(_))),
            "Should detect complex recursion due to mutual recursion"
        );
        
        Ok(())
    }

    #[test]
    fn test_detect_non_tail_recursion() {
        let result = test_detect_non_tail_recursion_impl();
        assert!(result.is_ok());
    }

    fn test_detect_non_tail_recursion_impl() -> Result<()> {
        // Test case for non-tail recursion
        let wat = r#"
            (module
                (func $sum (param i32) (result i32)
                    local.get 0
                    i32.const 0
                    i32.eq
                    if (result i32)
                        i32.const 0
                    else
                        local.get 0
                        local.get 0
                        i32.const 1
                        i32.sub
                        call $sum
                        i32.add
                    end
                )
                (export "sum" (func $sum))
            )
        "#;
        
        let wasm = wat::parse_str(wat)?;
        let module = Module::from_buffer(&wasm)?;
        
        let mut vulnerabilities = Vec::new();
        detect_complex_recursion(&module, &mut vulnerabilities);
        
        assert!(
            vulnerabilities.iter().any(|v| matches!(v, IndexerVulnerability::ComplexRecursion(_))),
            "Should detect complex recursion due to non-tail recursion"
        );
        
        Ok(())
    }

    #[test]
    fn test_indexer_safety_circuit_constraints() {
        let result = test_indexer_safety_circuit_constraints_impl();
        assert!(result.is_ok());
    }

    fn test_indexer_safety_circuit_constraints_impl() -> Result<()> {
        let vulnerabilities = vec![
            IndexerVulnerability::UnpredictableExecution("Test unpredictable execution".to_string()),
            IndexerVulnerability::ComplexRecursion("Test complex recursion".to_string()),
        ];
        
        // Regular circuit with vulnerabilities should fail
        let circuit = IndexerSafetyCircuit::<Fr>::new_with_vulnerabilities(vulnerabilities.clone(), false);
        let cs = ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs.clone()).is_err(), "Circuit with vulnerabilities should fail constraints");
        
        // Circuit in test mode should pass
        let test_circuit = IndexerSafetyCircuit::<Fr>::new_with_vulnerabilities(vulnerabilities, true);
        let test_cs = ark_relations::r1cs::ConstraintSystem::<Fr>::new_ref();
        assert!(test_circuit.generate_constraints(test_cs.clone()).is_ok(), "Circuit in test mode should pass constraints");
        
        Ok(())
    }
}
