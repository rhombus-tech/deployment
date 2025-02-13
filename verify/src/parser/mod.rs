pub mod types;
pub use types::{ValueType, BlockType, FunctionType, GlobalType, Stack, TypeContext};

pub mod cfg;
pub use cfg::{ControlFlowGraph, BasicBlock};

use walrus::{Module, FunctionId, Function};
use anyhow::Result;

/// Core WASM parser that provides analysis capabilities
pub struct Parser {
    module: Module,
}

impl Parser {
    pub fn new(module: Module) -> Self {
        Self { module }
    }

    pub fn get_module(&self) -> &Module {
        &self.module
    }

    pub fn get_module_mut(&mut self) -> &mut Module {
        &mut self.module
    }

    pub fn build_cfgs(&self) -> Result<Vec<ControlFlowGraph>> {
        let mut cfgs = Vec::new();
        
        // Build CFG for each function
        for func in self.module.funcs.iter() {
            let cfg = ControlFlowGraph::from_function(func)?;
            cfgs.push(cfg);
        }
        
        Ok(cfgs)
    }

    pub fn validate_function(&mut self, func_id: FunctionId) -> Result<()> {
        // Take ownership of the module temporarily
        let module = std::mem::replace(&mut self.module, Module::default());
        
        // Create context and validate
        let mut ctx = TypeContext::from_module(module, func_id)?;
        
        // Take back ownership of the module
        self.module = std::mem::replace(ctx.get_module_mut(), Module::default());
        
        Ok(())
    }
}

/// Analysis of memory operations
pub struct MemoryAnalysis {}

impl MemoryAnalysis {
    pub fn new() -> Self {
        Self {}
    }

    pub fn analyze_function(&mut self, _func: &Function) -> Result<()> {
        // Will implement memory analysis
        Ok(())
    }
}

/// Analysis of types and type checking
pub struct TypeAnalysis {}

impl TypeAnalysis {
    pub fn new() -> Self {
        Self {}
    }

    pub fn analyze_function(&mut self, _func: &Function) -> Result<()> {
        // Will implement type analysis
        Ok(())
    }
}

#[cfg(test)]
mod tests {}
