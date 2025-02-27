pub mod memory;
pub mod types;
#[cfg(test)]
pub mod tests;

use anyhow::{Result, Error};
use ethers::types::{Bytes, H160, H256, U256};
use serde::{Deserialize, Serialize};

use self::memory::MemoryAnalyzer;
use self::types::{ConstructorAnalysis, RuntimeAnalysis, StorageAccess, DelegateCall};

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
    /// Current call depth
    call_depth: u32,
    /// Call stack for tracking parent-child relationships
    call_stack: Vec<usize>,
    /// Current gas remaining
    gas_remaining: U256,
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
            call_depth: 0,
            call_stack: Vec::new(),
            gas_remaining: U256::from(1_000_000), // Initial gas limit
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

    /// Record delegate call
    fn record_delegate_call(
        &mut self,
        pc: u64,
        stack: &[U256],
    ) -> Result<()> {
        // DELEGATECALL stack: [gas, target, in_offset, in_size, out_offset, out_size]
        if stack.len() < 6 {
            println!("Stack underflow in record_delegate_call! Stack size: {}", stack.len());
            self.warnings.push(String::from("Stack underflow in DELEGATECALL operation"));
            return Ok(());
        }

        // Stack values are in LIFO order (last 6 items)
        // Values were pushed in reverse order, so we need to read them in reverse
        let gas_limit = stack[stack.len() - 1];
        let target = stack[stack.len() - 2];
        let in_offset = stack[stack.len() - 3];
        let in_size = stack[stack.len() - 4];
        let out_offset = stack[stack.len() - 5];
        let out_size = stack[stack.len() - 6];
        
        // Record memory accesses for input and output data
        self.record_memory_access(in_offset, in_size, false, None)?;
        self.record_memory_access(out_offset, out_size, true, None)?;

        // Convert target to H160 by taking the last 20 bytes
        let mut bytes = [0u8; 32];
        target.to_big_endian(&mut bytes);
        let target = H160::from_slice(&bytes[12..32]); // Take last 20 bytes

        // Get parent call ID if we're in a nested call
        let parent_call_id = if !self.call_stack.is_empty() {
            Some(*self.call_stack.last().unwrap())
        } else {
            None
        };

        // Create delegate call record
        let delegate_call = DelegateCall {
            target,
            pc,
            data_offset: in_offset,
            data_size: in_size,
            return_offset: out_offset,
            return_size: out_size,
            state_modifications: Vec::new(),
            parent_call_id,
            child_call_ids: Vec::new(),
            gas_limit,
            gas_used: U256::zero(),
            depth: self.call_depth,
        };

        // Add to runtime analysis
        let current_call_id = self.runtime.delegate_calls.len();
        self.runtime.delegate_calls.push(delegate_call);

        // Update parent's child_call_ids if this is a nested call
        if let Some(parent_id) = parent_call_id {
            if let Some(parent_call) = self.runtime.delegate_calls.get_mut(parent_id) {
                parent_call.child_call_ids.push(current_call_id);
            }
        }

        // Update call stack and depth
        self.call_stack.push(current_call_id);
        self.call_depth += 1;

        // Update gas tracking
        self.gas_remaining = self.gas_remaining.saturating_sub(gas_limit);

        Ok(())
    }

    /// Handle completion of a delegate call
    fn complete_delegate_call(&mut self, gas_used: U256) -> Result<()> {
        if let Some(current_call_id) = self.call_stack.pop() {
            // Update gas usage for the current call
            let current_call = &mut self.runtime.delegate_calls[current_call_id];
            current_call.gas_used = gas_used;
            
            // Return unused gas to parent
            let unused_gas = current_call.gas_limit.saturating_sub(gas_used);
            self.gas_remaining = self.gas_remaining.saturating_add(unused_gas);

            // Decrease call depth
            self.call_depth = self.call_depth.saturating_sub(1);

            // If we have a parent call, update its gas tracking
            if let Some(parent_id) = current_call.parent_call_id {
                let parent_call = &mut self.runtime.delegate_calls[parent_id];
                parent_call.gas_used = parent_call.gas_used.saturating_add(gas_used);
            }
        } else {
            self.warnings.push(String::from("Call stack underflow when completing delegate call"));
        }
        Ok(())
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
                0x3e => { // RETURNDATACOPY
                    if stack.len() < 3 {
                        self.warnings.push(String::from("Stack underflow in RETURNDATACOPY operation"));
                    } else {
                        let size = stack.pop().unwrap();
                        let dest_offset = stack.pop().unwrap();
                        let _ = stack.pop(); // offset
                        self.record_memory_access(dest_offset, size, true, None)?;
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
                0x5a => { // GAS
                    // Push remaining gas onto stack
                    stack.push(self.gas_remaining);
                    pc += 1;
                }
                0xf1 | 0xf2 | 0xf4 => { // CALL, CALLCODE, DELEGATECALL
                    has_external_call = true;
                    self.memory.record_external_call(pc as usize);
                    if bytecode[pc as usize] == 0xf4 {
                        println!("Found DELEGATECALL at pc: {}, stack size: {}", pc, stack.len());
                        if stack.len() >= 6 {
                            // First record the delegate call
                            self.record_delegate_call(pc, &stack)?;
                            println!("Recorded delegate call, current depth: {}, call stack: {:?}", self.call_depth, self.call_stack);
                            
                            // Pop the stack items AFTER recording (since record_delegate_call needs them)
                            for _ in 0..6 {
                                stack.pop();
                            }
                            
                            // Push success value (1 for now)
                            // Note: In EVM, success value is 0 for failure, 1 for success
                            stack.push(U256::one());
                            
                            // Calculate gas used for this call
                            let gas_used = U256::from(1_000_000)  // Initial gas
                                .saturating_sub(self.gas_remaining);
                            
                            // Record gas usage for the current call
                            if let Some(current_call_id) = self.call_stack.last() {
                                self.runtime.delegate_calls[*current_call_id].gas_used = gas_used;
                            }
                            
                            // Continue executing the next instruction
                            pc += 1;
                            continue;
                        } else {
                            println!("Stack underflow in DELEGATECALL! Stack size: {}", stack.len());
                            self.warnings.push(String::from("Stack underflow in DELEGATECALL operation"));
                            pc += 1;
                            continue;
                        }
                    }
                    pc += 1;
                }
                0xf3 => { // RETURN
                    if stack.len() < 2 {
                        self.warnings.push(String::from("Stack underflow in RETURN operation"));
                    } else {
                        let size = stack.pop().unwrap();
                        let offset = stack.pop().unwrap();
                        self.record_memory_access(offset, size, false, None)?;
                        
                        // Calculate gas used for this call
                        let gas_used = U256::from(1_000_000)  // Initial gas
                            .saturating_sub(self.gas_remaining);
                        
                        println!("Found RETURN at pc: {}, call depth: {}, call stack: {:?}", pc, self.call_depth, self.call_stack);
                        
                        // Handle return from delegate call
                        if !self.call_stack.is_empty() {
                            self.complete_delegate_call(gas_used)?;
                            println!("Completed delegate call, new depth: {}, call stack: {:?}", self.call_depth, self.call_stack);
                            
                            // Continue execution after returning from the call
                            pc += 1;
                            continue;
                        }
                        
                        println!("Not in delegate call, ending execution");
                        // If not in a delegate call, end execution
                        break;
                    }
                    pc += 1;
                }
                0xfd => { // REVERT
                    if stack.len() < 2 {
                        self.warnings.push(String::from("Stack underflow in REVERT operation"));
                    } else {
                        let size = stack.pop().unwrap();
                        let offset = stack.pop().unwrap();
                        self.record_memory_access(offset, size, false, None)?;
                        
                        // Calculate gas used for this call
                        let gas_used = U256::from(1_000_000)  // Initial gas
                            .saturating_sub(self.gas_remaining);
                        
                        // Handle return from delegate call
                        if !self.call_stack.is_empty() {
                            self.complete_delegate_call(gas_used)?;
                        }
                        
                        // End execution
                        break;
                    }
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
            delegate_calls: self.runtime.delegate_calls.clone(),
            ..Default::default()
        })
    }
}
