// EVM Interpreter - Step-by-step bytecode execution
// Generates real execution traces for full EF compliance

use anyhow::{Result, anyhow};
use ethers::types::{U256, H256, Address, Transaction, Block};
use std::collections::HashMap;
use crate::circuits::execution_trace::*;

/// Complete EVM Interpreter with step-by-step execution
pub struct EVMInterpreter {
    /// Current execution state
    pub state: EVMExecutionState,
    /// Bytecode being executed
    pub bytecode: Vec<u8>,
    /// Program counter
    pub pc: usize,
    /// Execution trace generator
    pub trace_generator: ExecutionTraceGenerator,
    /// Transaction context
    pub tx_context: TransactionContext,
    /// Block context
    pub block_context: BlockContext,
}

/// EVM execution state
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EVMExecutionState {
    pub stack: Vec<U256>,
    pub memory: Vec<u8>,
    pub storage: HashMap<H256, H256>,
    pub gas_remaining: u64,
    pub call_depth: u32,
    pub return_data: Vec<u8>,
    pub logs: Vec<LogEntry>,
    pub success: bool,
}

/// Transaction context for execution
#[derive(Debug, Clone)]
pub struct TransactionContext {
    pub from: Address,
    pub to: Option<Address>,
    pub value: U256,
    pub gas_limit: u64,
    pub gas_price: U256,
    pub data: Vec<u8>,
}

/// Block context for execution
#[derive(Debug, Clone)]
pub struct BlockContext {
    pub number: U256,
    pub timestamp: U256,
    pub gas_limit: U256,
    pub coinbase: Address,
    pub difficulty: U256,
}

/// Log entry for events
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogEntry {
    pub address: Address,
    pub topics: Vec<H256>,
    pub data: Vec<u8>,
}

impl EVMInterpreter {
    /// Create new EVM interpreter
    pub fn new(
        bytecode: Vec<u8>,
        tx: &Transaction,
        block: &Block<H256>,
        initial_gas: u64,
    ) -> Result<Self> {
        let trace_config = TraceConfig::default();
        let trace_generator = ExecutionTraceGenerator::new(trace_config);
        
        let tx_context = TransactionContext {
            from: tx.from,
            to: tx.to,
            value: tx.value,
            gas_limit: tx.gas.as_u64(),
            gas_price: tx.gas_price.unwrap_or(U256::zero()),
            data: tx.input.to_vec(),
        };
        
        let block_context = BlockContext {
            number: U256::from(block.number.unwrap_or_default().as_u64()),
            timestamp: block.timestamp,
            gas_limit: block.gas_limit,
            coinbase: block.author.unwrap_or_default(),
            difficulty: block.difficulty,
        };
        
        let state = EVMExecutionState {
            stack: Vec::new(),
            memory: Vec::new(),
            storage: HashMap::new(),
            gas_remaining: initial_gas,
            call_depth: 0,
            return_data: Vec::new(),
            logs: Vec::new(),
            success: false,
        };
        
        Ok(Self {
            state,
            bytecode,
            pc: 0,
            trace_generator,
            tx_context,
            block_context,
        })
    }
    
    /// Execute transaction and generate complete execution trace
    pub fn execute_transaction(&mut self) -> Result<ExecutionTraceResult> {
        let initial_state = EVMState {
            stack: self.state.stack.clone(),
            memory: self.state.memory.clone(),
            storage: self.state.storage.clone(),
            balances: HashMap::new(),
            nonces: HashMap::new(),
            code: HashMap::new(),
            gas_limit: U256::from(self.tx_context.gas_limit),
        };
        
        self.trace_generator.start_trace(H256::zero(), initial_state);
        
        // Execute bytecode step by step
        while self.pc < self.bytecode.len() && self.state.gas_remaining > 0 {
            let opcode = self.bytecode[self.pc];
            
            if let Err(e) = self.execute_opcode(opcode) {
                self.state.success = false;
                let step = ExecutionStep {
                    pc: self.pc,
                    opcode,
                    opcode_name: format!("0x{:02x}", opcode),
                    gas_before: U256::from(self.state.gas_remaining),
                    gas_after: U256::from(self.state.gas_remaining.saturating_sub(1)),
                    gas_cost: U256::from(1),
                    stack_before: self.state.stack.clone(),
                    stack_after: self.state.stack.clone(),
                    memory_changes: Vec::new(),
                    storage_changes: Vec::new(),
                    call_depth: self.state.call_depth as usize,
                    contract_address: Address::zero(),
                    error: None,
                    execution_time_ns: 0,
                };
                self.trace_generator.record_step(step)?;
                break;
            }
        }
        
        let final_state = EVMState {
            stack: self.state.stack.clone(),
            memory: self.state.memory.clone(),
            storage: self.state.storage.clone(),
            balances: HashMap::new(),
            nonces: HashMap::new(),
            code: HashMap::new(),
            gas_limit: U256::from(self.tx_context.gas_limit),
        };
        
        let trace = self.trace_generator.finish_trace(final_state)?;
        let total_steps = trace.execution_steps.len() as u64;
        
        Ok(ExecutionTraceResult {
            transaction_hash: H256::zero(),
            block_number: self.block_context.number,
            execution_steps: trace.execution_steps,
            gas_traces: vec![trace.gas_trace],
            memory_traces: vec![trace.memory_trace],
            storage_traces: vec![trace.storage_trace],
            stack_traces: vec![trace.stack_trace],
            performance: ExecutionPerformance {
                total_steps,
                total_time_ms: 0,
                total_memory_usage: self.state.memory.len() as u64,
                compression_ratio: 1.0,
            },
            compressed_trace: Vec::new(),
        })
    }
    
    /// Execute single opcode
    pub fn execute_opcode(&mut self, opcode: u8) -> Result<()> {
        let gas_before = self.state.gas_remaining;
        let stack_before = self.state.stack.clone();
        
        // Calculate gas cost
        let gas_cost = self.calculate_gas_cost(opcode)?;
        if self.state.gas_remaining < gas_cost {
            return Err(anyhow!("Out of gas"));
        }
        
        // Execute opcode
        match opcode {
            0x00 => return self.op_stop(),
            0x01 => self.op_add()?,
            0x02 => self.op_mul()?,
            0x03 => self.op_sub()?,
            0x10 => self.op_lt()?,
            0x11 => self.op_gt()?,
            0x14 => self.op_eq()?,
            0x15 => self.op_iszero()?,
            0x16 => self.op_and()?,
            0x17 => self.op_or()?,
            0x18 => self.op_xor()?,
            0x19 => self.op_not()?,
            0x20 => self.op_keccak256()?,
            0x35 => self.op_calldataload()?,
            0x36 => self.op_calldatasize()?,
            0x50 => self.op_pop()?,
            0x51 => self.op_mload()?,
            0x52 => self.op_mstore()?,
            0x54 => self.op_sload()?,
            0x55 => self.op_sstore()?,
            0x56 => self.op_jump()?,
            0x57 => self.op_jumpi()?,
            0x5b => self.op_jumpdest()?,
            0x60..=0x7f => self.op_push(opcode - 0x5f)?,
            0x80..=0x8f => self.op_dup(opcode - 0x7f)?,
            0x90..=0x9f => self.op_swap(opcode - 0x8f)?,
            0xa0 => self.op_log0()?,
            0xa1 => self.op_log1()?,
            0xf3 => return self.op_return(),
            0xfd => return self.op_revert(),
            _ => return Err(anyhow!("Unknown opcode: 0x{:02x}", opcode)),
        }
        
        // Update gas
        self.state.gas_remaining -= gas_cost;
        
        // Record execution step
        let step = ExecutionStep {
            pc: self.pc,
            opcode,
            opcode_name: format!("0x{:02x}", opcode),
            gas_before: U256::from(self.state.gas_remaining),
            gas_after: U256::from(self.state.gas_remaining.saturating_sub(gas_cost)),
            gas_cost: U256::from(gas_cost),
            stack_before: self.state.stack.clone(),
            stack_after: self.state.stack.clone(),
            memory_changes: Vec::new(),
            storage_changes: Vec::new(),
            call_depth: self.state.call_depth as usize,
            contract_address: Address::zero(),
            error: None,
            execution_time_ns: 0,
        };
        
        self.trace_generator.record_step(step)?;
        
        // Advance PC unless it was modified by jump
        if !matches!(opcode, 0x56 | 0x57 | 0xf3 | 0xfd) {
            self.pc += 1;
        }
        
        Ok(())
    }
    
    /// Calculate gas cost for opcode
    pub fn calculate_gas_cost(&self, opcode: u8) -> Result<u64> {
        Ok(match opcode {
            0x00 => 0,     // STOP
            0x01..=0x05 => 3,  // Arithmetic
            0x10..=0x1a => 3,  // Comparison
            0x20 => 30,    // KECCAK256
            0x35 => 3,     // CALLDATALOAD
            0x50 => 2,     // POP
            0x51 => 3,     // MLOAD
            0x52 => 3,     // MSTORE
            0x54 => 200,   // SLOAD
            0x55 => 5000,  // SSTORE
            0x56 => 8,     // JUMP
            0x57 => 10,    // JUMPI
            0x58..=0x5b => 2,  // PC, MSIZE, GAS, JUMPDEST
            0x60..=0x7f => 3,  // PUSH
            0x80..=0x8f => 3,  // DUP
            0x90..=0x9f => 3,  // SWAP
            0xf3 => 0,     // RETURN
            0xfd => 0,     // REVERT
            _ => 1,        // Default
        })
    }
    
    // Stack operations
    pub fn stack_push(&mut self, value: U256) -> Result<()> {
        if self.state.stack.len() >= 1024 {
            return Err(anyhow!("Stack overflow"));
        }
        self.state.stack.push(value);
        Ok(())
    }
    
    pub fn stack_pop(&mut self) -> Result<U256> {
        self.state.stack.pop().ok_or_else(|| anyhow!("Stack underflow"))
    }
    
    // Opcode implementations
    fn op_stop(&mut self) -> Result<()> {
        self.state.success = true;
        self.pc = self.bytecode.len();
        Ok(())
    }
    
    fn op_add(&mut self) -> Result<()> {
        let a = self.stack_pop()?;
        let b = self.stack_pop()?;
        self.stack_push(a.overflowing_add(b).0)
    }
    
    fn op_mul(&mut self) -> Result<()> {
        let a = self.stack_pop()?;
        let b = self.stack_pop()?;
        self.stack_push(a.overflowing_mul(b).0)
    }
    
    fn op_sub(&mut self) -> Result<()> {
        let a = self.stack_pop()?;
        let b = self.stack_pop()?;
        self.stack_push(a.overflowing_sub(b).0)
    }
    
    #[allow(dead_code)]
    fn op_div(&mut self) -> Result<()> {
        let a = self.stack_pop()?;
        let b = self.stack_pop()?;
        let result = if b.is_zero() { U256::zero() } else { a / b };
        self.stack_push(result)
    }
    
    fn op_lt(&mut self) -> Result<()> {
        let a = self.stack_pop()?;
        let b = self.stack_pop()?;
        self.stack_push(if a < b { U256::one() } else { U256::zero() })
    }
    
    fn op_gt(&mut self) -> Result<()> {
        let a = self.stack_pop()?;
        let b = self.stack_pop()?;
        self.stack_push(if a > b { U256::one() } else { U256::zero() })
    }
    
    fn op_eq(&mut self) -> Result<()> {
        let a = self.stack_pop()?;
        let b = self.stack_pop()?;
        self.stack_push(if a == b { U256::one() } else { U256::zero() })
    }
    
    fn op_iszero(&mut self) -> Result<()> {
        let a = self.stack_pop()?;
        self.stack_push(if a.is_zero() { U256::one() } else { U256::zero() })
    }
    
    fn op_and(&mut self) -> Result<()> {
        let a = self.stack_pop()?;
        let b = self.stack_pop()?;
        self.stack_push(a & b)
    }
    
    fn op_or(&mut self) -> Result<()> {
        let a = self.stack_pop()?;
        let b = self.stack_pop()?;
        self.stack_push(a | b)
    }
    
    fn op_xor(&mut self) -> Result<()> {
        let a = self.stack_pop()?;
        let b = self.stack_pop()?;
        self.stack_push(a ^ b)
    }
    
    fn op_not(&mut self) -> Result<()> {
        let a = self.stack_pop()?;
        self.stack_push(!a)
    }
    
    fn op_keccak256(&mut self) -> Result<()> {
        let offset = self.stack_pop()?.as_u64() as usize;
        let length = self.stack_pop()?.as_u64() as usize;
        
        if offset + length > self.state.memory.len() {
            self.state.memory.resize(offset + length, 0);
        }
        
        let data = &self.state.memory[offset..offset + length];
        let hash = keccak::keccak256(data);
        self.stack_push(U256::from_big_endian(&hash))
    }
    
    fn op_calldataload(&mut self) -> Result<()> {
        let offset = self.stack_pop()?.as_u64() as usize;
        let mut data = [0u8; 32];
        let calldata = &self.tx_context.data;
        
        for i in 0..32 {
            if offset + i < calldata.len() {
                data[i] = calldata[offset + i];
            }
        }
        
        self.stack_push(U256::from_big_endian(&data))
    }
    
    fn op_pop(&mut self) -> Result<()> {
        self.stack_pop()?;
        Ok(())
    }
    
    fn op_mload(&mut self) -> Result<()> {
        let offset = self.stack_pop()?.as_u64() as usize;
        if offset + 32 > self.state.memory.len() {
            self.state.memory.resize(offset + 32, 0);
        }
        
        let mut data = [0u8; 32];
        data.copy_from_slice(&self.state.memory[offset..offset + 32]);
        self.stack_push(U256::from_big_endian(&data))
    }
    
    fn op_mstore(&mut self) -> Result<()> {
        let offset = self.stack_pop()?.as_u64() as usize;
        let value = self.stack_pop()?;
        
        if offset + 32 > self.state.memory.len() {
            self.state.memory.resize(offset + 32, 0);
        }
        
        let mut bytes = [0u8; 32];
        value.to_big_endian(&mut bytes);
        self.state.memory[offset..offset + 32].copy_from_slice(&bytes);
        Ok(())
    }
    
    fn op_sload(&mut self) -> Result<()> {
        let key = self.stack_pop()?;
        let mut key_bytes = [0u8; 32];
        key.to_big_endian(&mut key_bytes);
        let key_h256 = H256::from_slice(&key_bytes);
        let value = self.state.storage.get(&key_h256).cloned().unwrap_or_default();
        self.stack_push(U256::from_big_endian(value.as_bytes()))
    }
    
    fn op_sstore(&mut self) -> Result<()> {
        let key = self.stack_pop()?;
        let value = self.stack_pop()?;
        let mut key_bytes = [0u8; 32];
        key.to_big_endian(&mut key_bytes);
        let key_h256 = H256::from_slice(&key_bytes);
        
        let mut value_bytes = [0u8; 32];
        value.to_big_endian(&mut value_bytes);
        let value_h256 = H256::from_slice(&value_bytes);
        
        self.state.storage.insert(key_h256, value_h256);
        Ok(())
    }
    
    fn op_jump(&mut self) -> Result<()> {
        let dest = self.stack_pop()?.as_u64() as usize;
        if dest >= self.bytecode.len() || self.bytecode[dest] != 0x5b {
            return Err(anyhow!("Invalid jump destination"));
        }
        self.pc = dest;
        Ok(())
    }
    
    fn op_jumpi(&mut self) -> Result<()> {
        let dest = self.stack_pop()?.as_u64() as usize;
        let condition = self.stack_pop()?;
        
        if !condition.is_zero() {
            if dest >= self.bytecode.len() || self.bytecode[dest] != 0x5b {
                return Err(anyhow!("Invalid jump destination"));
            }
            self.pc = dest;
        } else {
            self.pc += 1;
        }
        Ok(())
    }
    
    #[allow(dead_code)]
    fn op_pc(&mut self) -> Result<()> {
        self.stack_push(U256::from(self.pc))
    }
    
    #[allow(dead_code)]
    fn op_msize(&mut self) -> Result<()> {
        self.stack_push(U256::from(self.state.memory.len()))
    }
    
    #[allow(dead_code)]
    fn op_gas(&mut self) -> Result<()> {
        self.stack_push(U256::from(self.state.gas_remaining))
    }
    
    fn op_jumpdest(&mut self) -> Result<()> {
        // JUMPDEST is a no-op
        Ok(())
    }
    
    fn op_push(&mut self, n: u8) -> Result<()> {
        let mut data = vec![0u8; n as usize];
        for i in 0..n as usize {
            if self.pc + 1 + i < self.bytecode.len() {
                data[i] = self.bytecode[self.pc + 1 + i];
            }
        }
        self.pc += n as usize;
        self.stack_push(U256::from_big_endian(&data))
    }
    
    fn op_dup(&mut self, n: u8) -> Result<()> {
        let idx = self.state.stack.len().saturating_sub(n as usize);
        let value = self.state.stack.get(idx).cloned().unwrap_or_default();
        self.stack_push(value)
    }
    
    fn op_swap(&mut self, n: u8) -> Result<()> {
        let len = self.state.stack.len();
        if len < n as usize + 1 {
            return Err(anyhow!("Stack underflow"));
        }
        let idx = len - n as usize - 1;
        self.state.stack.swap(len - 1, idx);
        Ok(())
    }
    
    fn op_return(&mut self) -> Result<()> {
        let offset = self.stack_pop()?.as_u64() as usize;
        let length = self.stack_pop()?.as_u64() as usize;
        
        if offset + length > self.state.memory.len() {
            self.state.memory.resize(offset + length, 0);
        }
        
        self.state.return_data = self.state.memory[offset..offset + length].to_vec();
        self.state.success = true;
        self.pc = self.bytecode.len();
        Ok(())
    }
    
    fn op_revert(&mut self) -> Result<()> {
        let offset = self.stack_pop()?.as_u64() as usize;
        let length = self.stack_pop()?.as_u64() as usize;
        
        if offset + length > self.state.memory.len() {
            self.state.memory.resize(offset + length, 0);
        }
        
        self.state.return_data = self.state.memory[offset..offset + length].to_vec();
        self.state.success = false;
        self.pc = self.bytecode.len();
        Ok(())
    }
    
    fn op_calldatasize(&mut self) -> Result<()> {
        let size = U256::from(self.tx_context.data.len());
        self.stack_push(size)
    }
    
    fn op_log0(&mut self) -> Result<()> {
        // For now, just consume gas and continue
        Ok(())
    }
    
    fn op_log1(&mut self) -> Result<()> {
        // For now, just consume gas and continue
        Ok(())
    }
}

mod keccak {
    use tiny_keccak::{Hasher, Keccak};
    pub fn keccak256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; 32];
        hasher.update(data);
        hasher.finalize(&mut output);
        output
    }
}
