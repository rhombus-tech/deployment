use anyhow::Result;
use walrus::{Module, FunctionId, MemoryId};
use walrus::ir::Instr;
use std::collections::{HashMap, HashSet};
use crate::parser::cfg::ControlFlowGraph;
use crate::parser::types::{ValueType, MemoryType, Limits};
use crate::circuits::type_safety::{BlockContext as TypeSafetyBlockContext, StackOp};
use crate::circuits::memory_safety::{MemoryAccess, MemoryInit};

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
}

impl WasmAnalyzer {
    /// Create a new analyzer from a module
    pub fn new(module: Module) -> Result<Self> {
        Ok(Self {
            module,
            memory_access: HashMap::new(),
            function_deps: HashMap::new(),
            function_ops: HashMap::new(),
        })
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

    /// Get the first memory in the module
    pub fn get_memory(&self) -> Option<MemoryId> {
        self.module.memories.iter().next().map(|m| m.id())
    }

    /// Get stack operations
    pub fn get_stack_ops(&self) -> Option<Vec<ValueType>> {
        None // TODO: Implement stack operation tracking
    }

    /// Get block contexts
    pub fn get_block_contexts(&self) -> Option<Vec<TypeSafetyBlockContext>> {
        None // TODO: Implement block context tracking
    }

    /// Get call graph
    pub fn get_call_graph(&self) -> Option<ControlFlowGraph> {
        None // TODO: Implement call graph analysis
    }

    /// Get resource usage statistics
    pub fn get_resource_usage(&self) -> ResourceUsage {
        ResourceUsage::default()
    }

    /// Get memory allocations
    pub fn get_memory_allocations(&self, memory_id: MemoryId) -> Option<Vec<(u32, u32)>> {
        None // TODO: Implement allocation tracking
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
                    let block = local.block(local.entry_block());
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
    use walrus::{Module, ValType, FunctionBuilder};
    use walrus::ir::{Load, Store, MemArg};

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
    fn test_analyzer_creation() -> Result<()> {
        let wasm = create_test_module();
        let analyzer = WasmAnalyzer::from_bytes(&wasm)?;
        
        // Check that we have a memory section
        let memory_id = analyzer.get_memory().expect("Module should have memory");
        let memory = analyzer.module.memories.get(memory_id);
        assert!(memory.import.is_none(), "Memory should be local");
        Ok(())
    }

    #[test]
    fn test_memory_analysis() -> Result<()> {
        let wasm = create_test_module();
        let mut analyzer = WasmAnalyzer::from_bytes(&wasm)?;
        analyzer.analyze()?;  // Need to analyze before checking
        
        // Check memory access patterns
        let memory_id = analyzer.get_memory().unwrap();
        let accesses = analyzer.get_memory_access(memory_id);
        assert!(accesses.is_some());
        let accesses = accesses.unwrap();
        assert_eq!(accesses.len(), 2); // One load and one store
        
        // Verify that both accesses are at offset 0 with size 2 bytes
        // The alignment value in the Wasm instructions is 2 (meaning align to 2 bytes)
        for (offset, size) in accesses {
            assert_eq!(offset, 0); // Both accesses at offset 0
            assert_eq!(size, 2);   // Size is 2 bytes since align = 2
        }
        
        // Check memory type
        let memory_type = analyzer.get_memory_type(memory_id)?;
        assert_eq!(memory_type.limits.min, 1);
        assert_eq!(memory_type.limits.max, Some(1));
        assert!(!memory_type.shared);
        
        Ok(())
    }

    #[test]
    fn test_real_wasm_module() -> Result<()> {
        // Read the test.wasm file
        let wasm = std::fs::read("test.wasm")?;
        let mut analyzer = WasmAnalyzer::from_bytes(&wasm)?;
        analyzer.analyze()?;

        // Print out module info
        println!("\nAnalyzing test.wasm:");
        
        // Print memory info
        if let Some(memory_id) = analyzer.get_memory() {
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
