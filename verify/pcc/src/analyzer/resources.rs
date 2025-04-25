use wasmparser::{WasmFeatures, Parser, Payload, Operator, OperatorsReader};
use crate::analyzer::Property;
use anyhow::{Result, Context};
use std::cmp::max;

pub struct ResourceBoundsProperty {
    // Default limits for WebAssembly modules
    pub max_allowed_stack_depth: u32,  // Maximum allowed stack depth
    pub max_allowed_memory: u32,       // Maximum allowed memory in pages (64KB each)
}

impl Default for ResourceBoundsProperty {
    fn default() -> Self {
        Self {
            max_allowed_stack_depth: 1024,  // Default max stack depth of 1024 entries
            max_allowed_memory: 256,       // Default 16MB (256 pages of 64KB)
        }
    }
}

#[derive(Debug)]
pub struct ResourceBoundsProof {
    pub within_limits: bool,
    pub max_stack_depth: u32,
    pub max_memory_usage: u32,
}

impl Property for ResourceBoundsProperty {
    type Proof = ResourceBoundsProof;

    fn verify(&self, wasm: &[u8], _features: &WasmFeatures) -> Result<Self::Proof> {
        // Create a resource analyzer to examine the WASM binary
        let mut analyzer = ResourceAnalyzer::new();
        analyzer.analyze_wasm(wasm)?;
        
        // Get the analysis results
        let max_stack_depth = analyzer.max_stack_depth;
        let max_memory_usage = analyzer.max_memory_pages;
        
        // Check if resource usage is within limits
        let within_limits = max_stack_depth <= self.max_allowed_stack_depth
            && max_memory_usage <= self.max_allowed_memory;
            
        Ok(ResourceBoundsProof {
            within_limits,
            max_stack_depth,
            max_memory_usage,
        })
    }
}

/// Analyzer that examines a WebAssembly module to determine its resource usage
pub struct ResourceAnalyzer {
    // Maximum stack depth observed during analysis
    pub max_stack_depth: u32,
    
    // Maximum memory pages allocated
    pub max_memory_pages: u32,
    
    // Current stack depth during analysis
    current_stack_depth: u32,
}

impl ResourceAnalyzer {
    /// Create a new resource analyzer
    pub fn new() -> Self {
        Self {
            max_stack_depth: 0,
            max_memory_pages: 0,
            current_stack_depth: 0,
        }
    }
    
    /// Analyze a WebAssembly binary to determine resource usage
    pub fn analyze_wasm(&mut self, wasm: &[u8]) -> Result<()> {
        let parser = Parser::new(0);
        
        for payload in parser.parse_all(wasm) {
            match payload? {
                Payload::CodeSectionEntry(body) => {
                    // Extract the operators reader from the function body and unwrap the Result
                    let operators = body.get_operators_reader()?;
                    self.analyze_function_body(operators)?;
                },
                Payload::MemorySection(memories) => {
                    for memory in memories {
                        let memory = memory?;
                        // Convert u64 to u32 safely with bounds checking
                        let initial_pages = u32::try_from(memory.initial)
                            .unwrap_or_else(|_| u32::MAX); // Default to max if overflow
                        
                        self.max_memory_pages = max(self.max_memory_pages, initial_pages);
                        
                        // If there's a maximum defined, that's the upper bound
                        if let Some(max_pages) = memory.maximum {
                            let max_pages_u32 = u32::try_from(max_pages)
                                .unwrap_or_else(|_| u32::MAX); // Default to max if overflow
                            self.max_memory_pages = max(self.max_memory_pages, max_pages_u32);
                        }
                    }
                },
                _ => {}
            }
        }
        
        Ok(())
    }
    
    /// Analyze a function body to determine stack usage
    fn analyze_function_body(&mut self, body: OperatorsReader) -> Result<()> {
        // Reset stack depth for this function
        self.current_stack_depth = 0;
        
        for op in body.into_iter() {
            let operator = op.context("Failed to read operator")?;
            self.analyze_operator(operator);
        }
        
        Ok(())
    }
    
    /// Analyze a WebAssembly operator to update stack depth
    fn analyze_operator(&mut self, op: Operator) {
        // Simplified stack effect calculation for some common operators
        match op {
            // Stack-neutral operations
            Operator::Nop => {},
            
            // Stack-consuming operations (reduce stack by 1)
            Operator::Drop => {
                if self.current_stack_depth > 0 {
                    self.current_stack_depth -= 1;
                }
            },
            
            // Stack-producing operations (increase stack by 1)
            Operator::I32Const { .. } | Operator::I64Const { .. } | 
            Operator::F32Const { .. } | Operator::F64Const { .. } => {
                self.current_stack_depth += 1;
                self.max_stack_depth = max(self.max_stack_depth, self.current_stack_depth);
            },
            
            // Binary operations: consume 2 values, produce 1 (net -1)
            Operator::I32Add | Operator::I32Sub | Operator::I32Mul | Operator::I32DivS | 
            Operator::I64Add | Operator::I64Sub | Operator::I64Mul | Operator::I64DivS | 
            Operator::F32Add | Operator::F32Sub | Operator::F32Mul | Operator::F32Div | 
            Operator::F64Add | Operator::F64Sub | Operator::F64Mul | Operator::F64Div => {
                if self.current_stack_depth >= 2 {
                    self.current_stack_depth -= 1;
                }
            },
            
            // Comparison operations: consume 2 values, produce 1 (net -1)
            Operator::I32Eq | Operator::I32Ne | Operator::I32LtS | Operator::I32GtS | 
            Operator::I64Eq | Operator::I64Ne | Operator::I64LtS | Operator::I64GtS | 
            Operator::F32Eq | Operator::F32Ne | Operator::F32Lt | Operator::F32Gt | 
            Operator::F64Eq | Operator::F64Ne | Operator::F64Lt | Operator::F64Gt => {
                if self.current_stack_depth >= 2 {
                    self.current_stack_depth -= 1;
                }
            },
            
            // Memory operations - track both stack effect and memory usage
            Operator::I32Load { .. } | Operator::I64Load { .. } | 
            Operator::F32Load { .. } | Operator::F64Load { .. } => {
                // Load consumes address (1) and produces value (1), net effect 0
                // We don't change stack depth here
            },
            
            Operator::I32Store { .. } | Operator::I64Store { .. } | 
            Operator::F32Store { .. } | Operator::F64Store { .. } => {
                // Store consumes value and address (2), produces nothing
                if self.current_stack_depth >= 2 {
                    self.current_stack_depth -= 2;
                }
            },
            
            // Memory size and growth operations
            Operator::MemoryGrow { .. } => {
                // Consumes 1, produces 1 - no net effect
            },
            
            Operator::MemorySize { .. } => {
                // Produces 1
                self.current_stack_depth += 1;
                self.max_stack_depth = max(self.max_stack_depth, self.current_stack_depth);
            },
            
            // Call operations (simplified - actual stack effect depends on function signature)
            Operator::Call { .. } => {
                // We'd need more context for accurate stack effect
                // Conservatively assume a small increase for safety
                self.current_stack_depth += 1;
                self.max_stack_depth = max(self.max_stack_depth, self.current_stack_depth);
            },
            
            // For other operations, conservatively assume they might increase stack depth
            _ => {
                self.current_stack_depth += 1;
                self.max_stack_depth = max(self.max_stack_depth, self.current_stack_depth);
            }
        }
    }
}
