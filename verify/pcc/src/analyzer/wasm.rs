use wasmparser::{Parser, Payload, Operator};
use anyhow::Result;
use common::MemoryAccessData;

/// Analyzes a WASM binary to extract memory operations
pub struct WasmAnalyzer {
    memory_accesses: Vec<MemoryAccessData>,
    stack: Vec<u64>,
}

impl WasmAnalyzer {
    pub fn new() -> Self {
        Self {
            memory_accesses: Vec::new(),
            stack: Vec::new(),
        }
    }

    /// Parse WASM binary and extract memory operations
    pub fn analyze_wasm(&mut self, wasm_binary: &[u8]) -> Result<()> {
        let parser = Parser::new(0);
        
        for payload in parser.parse_all(wasm_binary) {
            let payload = payload?;
            
            match payload {
                Payload::CodeSectionEntry(code) => {
                    // Parse function body for memory operations
                    for op in code.get_operators_reader()? {
                        match op? {
                            // Constants that may affect memory offsets
                            Operator::I32Const { value } => {
                                self.stack.push(value as u64);
                            }
                            Operator::I64Const { value } => {
                                self.stack.push(value as u64);
                            }

                            // Memory loads
                            Operator::I32Load { memarg } => {
                                if let Some(addr) = self.stack.pop() {
                                    self.memory_accesses.push(MemoryAccessData {
                                        offset: addr + memarg.offset as u64,
                                        size: 4,
                                        is_load: true,
                                    });
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
                            _ => {} // Ignore other operators
                        }
                    }
                }
                _ => {} // Ignore other sections
            }
        }
        
        Ok(())
    }

    /// Get the collected memory accesses
    pub fn get_memory_accesses(&self) -> &[MemoryAccessData] {
        &self.memory_accesses
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wat::parse_str;

    #[test]
    fn test_analyze_simple_wasm() -> Result<()> {
        // Simple WASM module with memory operations
        let wasm = parse_str(r#"
            (module
                (memory 1)
                (func (export "test")
                    i32.const 0
                    i32.load
                    i32.const 4
                    i64.const 42
                    i64.store
                )
            )"#)?;

        let mut analyzer = WasmAnalyzer::new();
        analyzer.analyze_wasm(&wasm)?;

        let accesses = analyzer.get_memory_accesses();
        assert_eq!(accesses.len(), 2);
        
        // Check load operation
        assert_eq!(accesses[0].offset, 0);
        assert_eq!(accesses[0].size, 4);
        assert!(accesses[0].is_load);
        
        // Check store operation
        assert_eq!(accesses[1].offset, 4);
        assert_eq!(accesses[1].size, 8);
        assert!(!accesses[1].is_load);

        Ok(())
    }
}
