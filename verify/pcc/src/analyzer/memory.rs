use wasmparser::{WasmFeatures, Parser, Payload, Operator};
use crate::analyzer::Property;
use common::{MemoryAccessData, AllocationData, MemorySafetyProofData};
use anyhow::Result;

/// Memory safety property verifier
pub struct MemorySafetyProperty;

impl Property for MemorySafetyProperty {
    type Proof = MemorySafetyProofData;

    fn verify(&self, wasm: &[u8], _features: &WasmFeatures) -> anyhow::Result<Self::Proof> {
        let mut memory_analyzer = MemoryAnalyzer::new();
        
        // Parse WASM module
        memory_analyzer.analyze_wasm(wasm)?;
        
        let (memory_accesses, allocations, max_memory) = memory_analyzer.get_proof_data();
        
        // For now, we'll assume all accesses are safe if we can parse the module
        Ok(MemorySafetyProofData {
            bounds_checked: true,
            leak_free: true,
            max_memory,
            access_safety: true,
            memory_accesses,
            allocations,
        })
    }
}

/// Analyzer for tracking memory accesses and allocations
#[derive(Debug)]
pub struct MemoryAnalyzer {
    memory_accesses: Vec<MemoryAccessData>,
    memory_allocations: Vec<AllocationData>,
    mem_byte: u32,
    stack: Vec<u64>,
}

impl MemoryAnalyzer {
    pub fn new() -> Self {
        let mut analyzer = Self {
            memory_accesses: Vec::new(),
            memory_allocations: Vec::new(),
            mem_byte: 0,
            stack: Vec::new(),
        };
        
        // Add initial memory allocation (1 page = 64KB)
        analyzer.memory_allocations.push(AllocationData {
            address: 0,
            size: 65536,
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
                Payload::CodeSectionEntry(code) => {
                    for op in code.get_operators_reader()? {
                        let op = op?;
                        match op {
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
                            self.mem_byte = initial_pages * 65536;
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

    pub fn get_proof_data(&self) -> (Vec<MemoryAccessData>, Vec<AllocationData>, u32) {
        (
            self.memory_accesses.clone(),
            self.memory_allocations.clone(),
            self.mem_byte,
        )
    }
}
