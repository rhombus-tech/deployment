pub mod memory;
pub mod types;
#[cfg(test)]
pub mod tests;

use anyhow::Result;
use ethers::types::{Bytes, H256, U256};

use self::memory::MemoryAnalyzer;
use self::types::{ConstructorAnalysis, RuntimeAnalysis, StorageAccess};

/// Bytecode analyzer for contract deployment
#[derive(Debug)]
pub struct BytecodeAnalyzer {
    /// Program counter
    pc: u64,
    /// Memory analyzer
    memory: MemoryAnalyzer,
    /// Constructor analysis
    constructor: ConstructorAnalysis,
    /// Runtime analysis
    runtime: RuntimeAnalysis,
    /// Bytecode
    bytecode: Bytes,
    /// Storage accesses
    storage_accesses: Vec<StorageAccess>,
    /// Warnings
    warnings: Vec<String>,
}

impl BytecodeAnalyzer {
    pub fn new(bytecode: Bytes) -> Self {
        Self {
            pc: 0,
            memory: MemoryAnalyzer::new(),
            constructor: ConstructorAnalysis::default(),
            runtime: RuntimeAnalysis::default(),
            bytecode,
            storage_accesses: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// Record memory allocation
    pub fn record_memory_allocation(&mut self, offset: U256, size: U256) -> Result<()> {
        self.memory.record_allocation(offset, size, self.pc as usize);
        Ok(())
    }

    /// Record memory access
    pub fn record_memory_access(&mut self, offset: U256, size: U256, write: bool, value: Option<U256>) -> Result<()> {
        self.memory.record_access(offset, size, self.pc as usize, write, value);
        Ok(())
    }

    pub fn get_constructor(&self) -> &ConstructorAnalysis {
        &self.constructor
    }

    pub fn get_runtime(&self) -> &RuntimeAnalysis {
        &self.runtime
    }

    pub fn get_memory(&self) -> &MemoryAnalyzer {
        &self.memory
    }

    /// Analyze bytecode
    pub fn analyze(&mut self) -> Result<RuntimeAnalysis> {
        // Reset state
        self.storage_accesses.clear();
        self.warnings.clear();

        let mut pc = 0;
        let bytecode = self.bytecode.clone(); // Clone the bytecode to avoid borrowing conflicts
        let bytecode = bytecode.as_ref();
        let mut stack: Vec<U256> = Vec::new();
        let mut has_external_call = false;

        while pc < bytecode.len() as u64 {
            match bytecode[pc as usize] {
                0x01 => { // ADD
                    if stack.len() < 2 {
                        self.warnings.push(String::from("Stack underflow in ADD operation"));
                    } else {
                        let a = stack.pop().unwrap();
                        let b = stack.pop().unwrap();
                        if let Some(sum) = a.checked_add(b) {
                            stack.push(sum);
                        } else {
                            self.memory.record_arithmetic_overflow(pc as usize);
                            stack.push(a.overflowing_add(b).0); // Push the wrapped value
                        }
                    }
                    pc += 1;
                }
                0x16 => { // AND
                    if stack.len() < 2 {
                        self.warnings.push(String::from("Stack underflow in AND operation"));
                    } else {
                        let a = stack.pop().unwrap();
                        let b = stack.pop().unwrap();
                        stack.push(a & b);
                    }
                    pc += 1;
                }
                0x17 => { // OR
                    if stack.len() < 2 {
                        self.warnings.push(String::from("Stack underflow in OR operation"));
                    } else {
                        let a = stack.pop().unwrap();
                        let b = stack.pop().unwrap();
                        stack.push(a | b);
                    }
                    pc += 1;
                }
                0x18 => { // XOR
                    if stack.len() < 2 {
                        self.warnings.push(String::from("Stack underflow in XOR operation"));
                    } else {
                        let a = stack.pop().unwrap();
                        let b = stack.pop().unwrap();
                        stack.push(a ^ b);
                    }
                    pc += 1;
                }
                0x51 => { // MLOAD
                    if stack.is_empty() {
                        self.warnings.push(String::from("Stack underflow in MLOAD operation"));
                    } else {
                        let offset = stack.pop().unwrap();
                        // First record the access
                        self.record_memory_access(offset, U256::from(32), false, None)?;
                        // Then get the value if it exists
                        if let Some(value) = self.memory.get_memory_value(offset) {
                            stack.push(value);
                        } else {
                            stack.push(U256::zero()); // Default to zero if no value found
                        }
                    }
                    pc += 1;
                }
                0x52 => { // MSTORE
                    if stack.len() < 2 {
                        self.warnings.push(String::from("Stack underflow in MSTORE operation"));
                    } else {
                        let value = stack.pop().unwrap();
                        let offset = stack.pop().unwrap();
                        // First record the write with the value
                        self.record_memory_access(offset, U256::from(32), true, Some(value))?;
                        // Then mark this range as initialized
                        self.memory.record_write_range(offset, U256::from(32));
                    }
                    pc += 1;
                }
                0x60..=0x7f => { // PUSH1-PUSH32
                    let bytes = (bytecode[pc as usize] - 0x60 + 1) as usize;
                    if pc + bytes as u64 + 1 <= bytecode.len() as u64 {
                        let mut value = U256::zero();
                        for i in 0..bytes {
                            value = value << 8;
                            value = value + U256::from(bytecode[(pc + 1 + i as u64) as usize]);
                        }
                        stack.push(value);
                    }
                    pc += bytes as u64 + 1;
                }
                0x37 => { // CALLDATACOPY
                    if stack.len() < 3 {
                        self.warnings.push(String::from("Stack underflow in CALLDATACOPY operation"));
                    } else {
                        let size = stack.pop().unwrap();
                        let offset = stack.pop().unwrap();
                        let _ = stack.pop(); // dataOffset
                        self.record_memory_access(offset, size, true, None)?;
                    }
                    pc += 1;
                }
                0x54 => { // SLOAD
                    if !stack.is_empty() {
                        let slot = stack.pop().unwrap();
                        self.storage_accesses.push(StorageAccess {
                            slot: H256::from_low_u64_be(slot.as_u64()),
                            value: None,
                            pc,
                            write: false,
                            is_init: false,
                        });
                    }
                    self.memory.record_state_read(pc as usize);
                    pc += 1;
                }
                0x55 => { // SSTORE
                    if stack.len() >= 2 {
                        let value = stack.pop().unwrap();
                        let slot = stack.pop().unwrap();
                        
                        // Convert U256 to H256 by taking the low 256 bits
                        let slot_h256 = H256::from_low_u64_be(slot.as_u64());
                        let value_h256 = H256::from_low_u64_be(value.as_u64());

                        self.storage_accesses.push(StorageAccess {
                            slot: slot_h256,
                            value: Some(value_h256),
                            pc,
                            write: true,
                            is_init: false,
                        });
                    }
                    self.memory.record_state_write(pc as usize);
                    pc += 1;
                }
                0x80..=0x8F => { // DUP1-DUP16
                    let pos = (bytecode[pc as usize] - 0x80 + 1) as usize;
                    if stack.len() < pos {
                        self.warnings.push(format!(
                            "Stack underflow in DUP{} operation",
                            pos
                        ));
                    } else {
                        let value = stack[stack.len() - pos];
                        stack.push(value);
                    }
                    pc += 1;
                }
                0x90..=0x9F => { // SWAP1-SWAP16
                    let pos = (bytecode[pc as usize] - 0x90 + 1) as usize;
                    if stack.len() < pos + 1 {
                        self.warnings.push(format!(
                            "Stack underflow in SWAP{} operation",
                            pos
                        ));
                    } else {
                        let len = stack.len();
                        stack.swap(len - 1, len - pos - 1);
                    }
                    pc += 1;
                }
                0xf1 | 0xf2 | 0xf4 => { // CALL, CALLCODE, DELEGATECALL
                    has_external_call = true;
                    self.memory.record_external_call(pc as usize);
                    pc += 1;
                }
                _ => pc += 1,
            }
        }

        // Add memory-related warnings
        let memory_warnings = self.memory.get_vulnerability_report();
        self.warnings.extend(memory_warnings);

        if has_external_call {
            let mut state_writes_after_call = false;
            let mut state_reads_before_call = false;
            
            for access in &self.storage_accesses {
                if access.pc < pc {
                    if !access.write {
                        state_reads_before_call = true;
                    }
                } else if access.write {
                    state_writes_after_call = true;
                }
            }
            
            if state_reads_before_call && state_writes_after_call {
                self.warnings.push(String::from(
                    "Potential reentrancy vulnerability: state update after external call"
                ));
            }
        }

        Ok(RuntimeAnalysis {
            code_offset: 0,
            code_length: self.bytecode.len(),
            storage_accesses: self.storage_accesses.clone(),
            warnings: self.warnings.clone(),
            ..Default::default()
        })
    }
}
