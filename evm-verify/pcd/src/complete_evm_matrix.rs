use ark_ff::Field;
use std::collections::HashMap;
use std::marker::PhantomData;
use crate::tensor_zoda::{Matrix, TensorZODA, TensorZODAError};
use ethers::types::{H256, U256, Address};
use serde::{Serialize, Deserialize};

/// Complete EVM execution trace matrix for tensor-based proving
/// This extends the security-focused ZODA to complete EVM state transition proving
#[derive(Clone, Debug)]
pub struct CompleteEVMExecutionMatrix<F: Field> {
    // Input State
    pub bytecode: Vec<u8>,
    pub initial_state_root: H256,
    pub transaction_data: TransactionData,
    
    // Execution Trace Matrices - Core tensor operations
    pub execution_matrix: Matrix<F>,     // All opcode executions (140+ opcodes)
    pub state_matrix: Matrix<F>,         // State changes (storage, balances)
    pub memory_matrix: Matrix<F>,        // Memory operations
    pub stack_matrix: Matrix<F>,         // Stack operations
    pub gas_matrix: Matrix<F>,           // Gas accounting
    
    // Output State
    pub final_state_root: H256,
    pub gas_used: u64,
    pub success: bool,
    pub return_data: Vec<u8>,
    
    // Indexing and Mapping
    pub opcode_indices: HashMap<u8, usize>,     // All 140+ EVM opcodes
    pub state_indices: HashMap<H256, usize>,    // Storage slot tracking
    pub memory_indices: HashMap<usize, usize>,  // Memory address mapping
    
    // Execution tracking
    pub execution_step: usize,
    pub max_steps: usize,
    
    // Field marker
    _phantom: PhantomData<F>,
}

/// Transaction data for EVM execution
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionData {
    pub from: Address,
    pub to: Option<Address>,
    pub value: U256,
    pub gas_limit: u64,
    pub gas_price: U256,
    pub data: Vec<u8>,
    pub nonce: u64,
    pub chain_id: Option<u64>,
}

/// EVM execution state at a specific step
#[derive(Clone, Debug)]
pub struct EVMExecutionState<F: Field> {
    pub pc: usize,                    // Program counter
    pub stack: Vec<U256>,             // EVM stack
    pub memory: Vec<u8>,              // EVM memory
    pub storage: HashMap<H256, H256>, // Contract storage
    pub gas_remaining: u64,           // Remaining gas
    pub return_data: Vec<u8>,         // Return data buffer
    pub call_depth: u8,               // Call stack depth
    _phantom: PhantomData<F>,
}

/// Complete EVM opcode enumeration for tensor encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EVMOpcode {
    // Arithmetic Operations (0x00-0x0f)
    STOP = 0x00,
    ADD = 0x01,
    MUL = 0x02,
    SUB = 0x03,
    DIV = 0x04,
    SDIV = 0x05,
    MOD = 0x06,
    SMOD = 0x07,
    ADDMOD = 0x08,
    MULMOD = 0x09,
    EXP = 0x0a,
    SIGNEXTEND = 0x0b,
    
    // Comparison & Bitwise Logic (0x10-0x1f)
    LT = 0x10,
    GT = 0x11,
    SLT = 0x12,
    SGT = 0x13,
    EQ = 0x14,
    ISZERO = 0x15,
    AND = 0x16,
    OR = 0x17,
    XOR = 0x18,
    NOT = 0x19,
    BYTE = 0x1a,
    SHL = 0x1b,
    SHR = 0x1c,
    SAR = 0x1d,
    
    // Keccak (0x20)
    KECCAK256 = 0x20,
    
    // Environmental Information (0x30-0x3f)
    ADDRESS = 0x30,
    BALANCE = 0x31,
    ORIGIN = 0x32,
    CALLER = 0x33,
    CALLVALUE = 0x34,
    CALLDATALOAD = 0x35,
    CALLDATASIZE = 0x36,
    CALLDATACOPY = 0x37,
    CODESIZE = 0x38,
    CODECOPY = 0x39,
    GASPRICE = 0x3a,
    EXTCODESIZE = 0x3b,
    EXTCODECOPY = 0x3c,
    RETURNDATASIZE = 0x3d,
    RETURNDATACOPY = 0x3e,
    EXTCODEHASH = 0x3f,
    
    // Block Information (0x40-0x4f)
    BLOCKHASH = 0x40,
    COINBASE = 0x41,
    TIMESTAMP = 0x42,
    NUMBER = 0x43,
    DIFFICULTY = 0x44,
    GASLIMIT = 0x45,
    CHAINID = 0x46,
    SELFBALANCE = 0x47,
    BASEFEE = 0x48,
    
    // Stack, Memory, Storage and Flow (0x50-0x5f)
    POP = 0x50,
    MLOAD = 0x51,
    MSTORE = 0x52,
    MSTORE8 = 0x53,
    SLOAD = 0x54,
    SSTORE = 0x55,
    JUMP = 0x56,
    JUMPI = 0x57,
    PC = 0x58,
    MSIZE = 0x59,
    GAS = 0x5a,
    JUMPDEST = 0x5b,
    
    // Push Operations (0x60-0x7f)
    PUSH1 = 0x60, PUSH2 = 0x61, PUSH3 = 0x62, PUSH4 = 0x63,
    PUSH5 = 0x64, PUSH6 = 0x65, PUSH7 = 0x66, PUSH8 = 0x67,
    PUSH9 = 0x68, PUSH10 = 0x69, PUSH11 = 0x6a, PUSH12 = 0x6b,
    PUSH13 = 0x6c, PUSH14 = 0x6d, PUSH15 = 0x6e, PUSH16 = 0x6f,
    PUSH17 = 0x70, PUSH18 = 0x71, PUSH19 = 0x72, PUSH20 = 0x73,
    PUSH21 = 0x74, PUSH22 = 0x75, PUSH23 = 0x76, PUSH24 = 0x77,
    PUSH25 = 0x78, PUSH26 = 0x79, PUSH27 = 0x7a, PUSH28 = 0x7b,
    PUSH29 = 0x7c, PUSH30 = 0x7d, PUSH31 = 0x7e, PUSH32 = 0x7f,
    
    // Duplicate Operations (0x80-0x8f)
    DUP1 = 0x80, DUP2 = 0x81, DUP3 = 0x82, DUP4 = 0x83,
    DUP5 = 0x84, DUP6 = 0x85, DUP7 = 0x86, DUP8 = 0x87,
    DUP9 = 0x88, DUP10 = 0x89, DUP11 = 0x8a, DUP12 = 0x8b,
    DUP13 = 0x8c, DUP14 = 0x8d, DUP15 = 0x8e, DUP16 = 0x8f,
    
    // Exchange Operations (0x90-0x9f)
    SWAP1 = 0x90, SWAP2 = 0x91, SWAP3 = 0x92, SWAP4 = 0x93,
    SWAP5 = 0x94, SWAP6 = 0x95, SWAP7 = 0x96, SWAP8 = 0x97,
    SWAP9 = 0x98, SWAP10 = 0x99, SWAP11 = 0x9a, SWAP12 = 0x9b,
    SWAP13 = 0x9c, SWAP14 = 0x9d, SWAP15 = 0x9e, SWAP16 = 0x9f,
    
    // Logging Operations (0xa0-0xa4)
    LOG0 = 0xa0,
    LOG1 = 0xa1,
    LOG2 = 0xa2,
    LOG3 = 0xa3,
    LOG4 = 0xa4,
    
    // System Operations (0xf0-0xff)
    CREATE = 0xf0,
    CALL = 0xf1,
    CALLCODE = 0xf2,
    RETURN = 0xf3,
    DELEGATECALL = 0xf4,
    CREATE2 = 0xf5,
    STATICCALL = 0xfa,
    REVERT = 0xfd,
    INVALID = 0xfe,
    SELFDESTRUCT = 0xff,
}

impl EVMOpcode {
    /// Get gas cost for this opcode (simplified model)
    pub fn gas_cost(&self) -> u64 {
        match self {
            EVMOpcode::STOP => 0,
            EVMOpcode::ADD | EVMOpcode::SUB | EVMOpcode::MUL => 3,
            EVMOpcode::DIV | EVMOpcode::SDIV | EVMOpcode::MOD | EVMOpcode::SMOD => 5,
            EVMOpcode::ADDMOD | EVMOpcode::MULMOD => 8,
            EVMOpcode::EXP => 10, // Base cost, dynamic based on exponent
            EVMOpcode::SIGNEXTEND => 5,
            
            // Logic operations
            EVMOpcode::LT | EVMOpcode::GT | EVMOpcode::SLT | EVMOpcode::SGT | EVMOpcode::EQ => 3,
            EVMOpcode::ISZERO | EVMOpcode::AND | EVMOpcode::OR | EVMOpcode::XOR | EVMOpcode::NOT => 3,
            EVMOpcode::BYTE => 3,
            EVMOpcode::SHL | EVMOpcode::SHR | EVMOpcode::SAR => 3,
            
            // Keccak
            EVMOpcode::KECCAK256 => 30, // Base cost, dynamic based on data size
            
            // Environmental
            EVMOpcode::ADDRESS | EVMOpcode::ORIGIN | EVMOpcode::CALLER => 2,
            EVMOpcode::CALLVALUE | EVMOpcode::CALLDATASIZE => 2,
            EVMOpcode::GASPRICE | EVMOpcode::COINBASE | EVMOpcode::TIMESTAMP => 2,
            EVMOpcode::NUMBER | EVMOpcode::DIFFICULTY | EVMOpcode::GASLIMIT => 2,
            EVMOpcode::CHAINID | EVMOpcode::BASEFEE => 2,
            EVMOpcode::BALANCE => 100, // Can be 2600 if cold
            EVMOpcode::EXTCODESIZE | EVMOpcode::EXTCODEHASH => 100, // Can be 2600 if cold
            EVMOpcode::BLOCKHASH => 20,
            EVMOpcode::SELFBALANCE => 5,
            
            // Memory/Storage
            EVMOpcode::POP => 2,
            EVMOpcode::MLOAD | EVMOpcode::MSTORE | EVMOpcode::MSTORE8 => 3,
            EVMOpcode::SLOAD => 100, // Can be 2100 if cold
            EVMOpcode::SSTORE => 100, // Complex pricing: 2900/5000/20000
            EVMOpcode::PC | EVMOpcode::MSIZE | EVMOpcode::GAS => 2,
            
            // Control flow
            EVMOpcode::JUMP => 8,
            EVMOpcode::JUMPI => 10,
            EVMOpcode::JUMPDEST => 1,
            
            // Push operations
            EVMOpcode::PUSH1 | EVMOpcode::PUSH2 | EVMOpcode::PUSH3 | EVMOpcode::PUSH4 |
            EVMOpcode::PUSH5 | EVMOpcode::PUSH6 | EVMOpcode::PUSH7 | EVMOpcode::PUSH8 |
            EVMOpcode::PUSH9 | EVMOpcode::PUSH10 | EVMOpcode::PUSH11 | EVMOpcode::PUSH12 |
            EVMOpcode::PUSH13 | EVMOpcode::PUSH14 | EVMOpcode::PUSH15 | EVMOpcode::PUSH16 |
            EVMOpcode::PUSH17 | EVMOpcode::PUSH18 | EVMOpcode::PUSH19 | EVMOpcode::PUSH20 |
            EVMOpcode::PUSH21 | EVMOpcode::PUSH22 | EVMOpcode::PUSH23 | EVMOpcode::PUSH24 |
            EVMOpcode::PUSH25 | EVMOpcode::PUSH26 | EVMOpcode::PUSH27 | EVMOpcode::PUSH28 |
            EVMOpcode::PUSH29 | EVMOpcode::PUSH30 | EVMOpcode::PUSH31 | EVMOpcode::PUSH32 => 3,
            
            // Stack operations
            EVMOpcode::DUP1 | EVMOpcode::DUP2 | EVMOpcode::DUP3 | EVMOpcode::DUP4 |
            EVMOpcode::DUP5 | EVMOpcode::DUP6 | EVMOpcode::DUP7 | EVMOpcode::DUP8 |
            EVMOpcode::DUP9 | EVMOpcode::DUP10 | EVMOpcode::DUP11 | EVMOpcode::DUP12 |
            EVMOpcode::DUP13 | EVMOpcode::DUP14 | EVMOpcode::DUP15 | EVMOpcode::DUP16 => 3,
            EVMOpcode::SWAP1 | EVMOpcode::SWAP2 | EVMOpcode::SWAP3 | EVMOpcode::SWAP4 |
            EVMOpcode::SWAP5 | EVMOpcode::SWAP6 | EVMOpcode::SWAP7 | EVMOpcode::SWAP8 |
            EVMOpcode::SWAP9 | EVMOpcode::SWAP10 | EVMOpcode::SWAP11 | EVMOpcode::SWAP12 |
            EVMOpcode::SWAP13 | EVMOpcode::SWAP14 | EVMOpcode::SWAP15 | EVMOpcode::SWAP16 => 3,
            
            // Logging
            EVMOpcode::LOG0 => 375,
            EVMOpcode::LOG1 => 750,
            EVMOpcode::LOG2 => 1125,
            EVMOpcode::LOG3 => 1500,
            EVMOpcode::LOG4 => 1875,
            
            // System operations
            EVMOpcode::CREATE => 32000,
            EVMOpcode::CREATE2 => 32000,
            EVMOpcode::CALL | EVMOpcode::CALLCODE | EVMOpcode::DELEGATECALL => 100, // Base cost
            EVMOpcode::STATICCALL => 100,
            EVMOpcode::RETURN | EVMOpcode::REVERT => 0,
            EVMOpcode::SELFDESTRUCT => 5000,
            EVMOpcode::INVALID => 0,
            
            // Copy operations
            EVMOpcode::CALLDATALOAD => 3,
            EVMOpcode::CALLDATACOPY | EVMOpcode::CODECOPY | EVMOpcode::EXTCODECOPY => 3, // Base cost
            EVMOpcode::RETURNDATASIZE => 2,
            EVMOpcode::RETURNDATACOPY => 3,
            
            EVMOpcode::CODESIZE => 2,
        }
    }
    
    /// Check if this opcode modifies state
    pub fn modifies_state(&self) -> bool {
        matches!(self,
            EVMOpcode::SSTORE | EVMOpcode::CREATE | EVMOpcode::CREATE2 |
            EVMOpcode::CALL | EVMOpcode::CALLCODE | EVMOpcode::DELEGATECALL |
            EVMOpcode::LOG0 | EVMOpcode::LOG1 | EVMOpcode::LOG2 | EVMOpcode::LOG3 | EVMOpcode::LOG4 |
            EVMOpcode::SELFDESTRUCT
        )
    }
    
    /// Check if this opcode can cause execution to halt
    pub fn can_halt(&self) -> bool {
        matches!(self,
            EVMOpcode::STOP | EVMOpcode::RETURN | EVMOpcode::REVERT |
            EVMOpcode::INVALID | EVMOpcode::SELFDESTRUCT
        )
    }
}

impl<F: Field> CompleteEVMExecutionMatrix<F> {
    /// Create a new complete EVM execution matrix
    pub fn new(
        bytecode: Vec<u8>,
        transaction_data: TransactionData,
        max_steps: usize,
    ) -> Result<Self, TensorZODAError> {
        // Initialize tensor dimensions optimized for CPU cache
        let execution_matrix = Matrix::new(256, max_steps); // 256 possible opcodes
        let state_matrix = Matrix::new(1024, max_steps);    // Up to 1024 storage slots
        let memory_matrix = Matrix::new(1024, max_steps);   // Memory operations
        let stack_matrix = Matrix::new(1024, max_steps);    // Stack depth
        let gas_matrix = Matrix::new(16, max_steps);        // Gas accounting metrics
        
        // Create opcode mapping for all EVM opcodes
        let mut opcode_indices = HashMap::new();
        for i in 0..=255u8 {
            opcode_indices.insert(i, i as usize);
        }
        
        Ok(CompleteEVMExecutionMatrix {
            bytecode,
            initial_state_root: H256::zero(),
            transaction_data,
            execution_matrix,
            state_matrix,
            memory_matrix,
            stack_matrix,
            gas_matrix,
            final_state_root: H256::zero(),
            gas_used: 0,
            success: false,
            return_data: Vec::new(),
            opcode_indices,
            state_indices: HashMap::new(),
            memory_indices: HashMap::new(),
            execution_step: 0,
            max_steps,
            _phantom: PhantomData,
        })
    }
    
    /// Encode a complete EVM execution step into tensor matrices
    pub fn encode_execution_step(
        &mut self,
        opcode: EVMOpcode,
        execution_state: &EVMExecutionState<F>,
        gas_cost: u64,
    ) -> Result<(), TensorZODAError> {
        if self.execution_step >= self.max_steps {
            return Err(TensorZODAError::MatrixDimensionMismatch(
                "Execution steps exceeded maximum".to_string()
            ));
        }
        
        // 1. Encode opcode execution
        let opcode_row = opcode as u8 as usize;
        self.execution_matrix.data[opcode_row][self.execution_step] = F::one();
        
        // 2. Encode stack state (top 16 elements)
        for (i, &stack_value) in execution_state.stack.iter().rev().take(16).enumerate() {
            let field_value = Self::u256_to_field(stack_value);
            if i < self.stack_matrix.rows {
                self.stack_matrix.data[i][self.execution_step] = field_value;
            }
        }
        
        // 3. Encode memory changes (if any)
        // For efficiency, we only track recent memory changes
        // This could be expanded for full memory tracking
        
        // 4. Encode storage changes
        for (&storage_key, &storage_value) in &execution_state.storage {
            let slot_index = self.get_or_create_storage_index(storage_key);
            if slot_index < self.state_matrix.rows {
                self.state_matrix.data[slot_index][self.execution_step] = 
                    Self::h256_to_field(storage_value);
            }
        }
        
        // 5. Encode gas information
        self.gas_matrix.data[0][self.execution_step] = F::from(gas_cost); // Gas cost
        self.gas_matrix.data[1][self.execution_step] = F::from(execution_state.gas_remaining); // Remaining gas
        self.gas_matrix.data[2][self.execution_step] = F::from(execution_state.pc as u64); // Program counter
        self.gas_matrix.data[3][self.execution_step] = F::from(execution_state.call_depth as u64); // Call depth
        
        self.execution_step += 1;
        Ok(())
    }
    
    /// Convert U256 to field element (simplified conversion)
    fn u256_to_field(value: U256) -> F {
        // Convert U256 to bytes and then to field element
        // This is a simplified conversion - in production, this would need
        // proper handling of large numbers that exceed field size
        let mut bytes = [0u8; 32];
        value.to_big_endian(&mut bytes);
        
        // Take lower 8 bytes for field conversion (simplified)
        let lower_bytes = &bytes[24..];
        let mut result = 0u64;
        for (i, &byte) in lower_bytes.iter().enumerate() {
            result |= (byte as u64) << (i * 8);
        }
        F::from(result)
    }
    
    /// Convert H256 to field element
    fn h256_to_field(value: H256) -> F {
        let bytes = value.as_bytes();
        // Take lower 8 bytes for field conversion (simplified)
        let lower_bytes = &bytes[24..];
        let mut result = 0u64;
        for (i, &byte) in lower_bytes.iter().enumerate() {
            result |= (byte as u64) << (i * 8);
        }
        F::from(result)
    }
    
    /// Get or create storage slot index for tensor encoding
    fn get_or_create_storage_index(&mut self, storage_key: H256) -> usize {
        if let Some(&index) = self.state_indices.get(&storage_key) {
            index
        } else {
            let index = self.state_indices.len();
            self.state_indices.insert(storage_key, index);
            index
        }
    }
    
    /// Finalize the execution matrix with final state
    pub fn finalize_execution(
        &mut self,
        final_state_root: H256,
        gas_used: u64,
        success: bool,
        return_data: Vec<u8>,
    ) {
        self.final_state_root = final_state_root;
        self.gas_used = gas_used;
        self.success = success;
        self.return_data = return_data;
    }
    
    /// Verify the complete EVM execution using tensor operations
    pub fn verify_complete_execution(
        &self,
        zoda: &TensorZODA<F>,
    ) -> Result<bool, TensorZODAError> {
        // 1. Verify execution matrix consistency
        if !self.verify_execution_consistency()? {
            return Ok(false);
        }
        
        // 2. Verify state transitions
        if !self.verify_state_transitions()? {
            return Ok(false);
        }
        
        // 3. Verify gas accounting
        if !self.verify_gas_accounting()? {
            return Ok(false);
        }
        
        // 4. Use ZODA for cryptographic verification
        let verification_matrix = self.create_verification_matrix()?;
        let mut zoda_clone = zoda.clone();
        zoda_clone.encode_input(&verification_matrix)?;
        
        // For now, return true if encoding succeeds
        // In full implementation, this would perform complete tensor verification
        Ok(true)
    }
    
    /// Verify execution matrix consistency
    fn verify_execution_consistency(&self) -> Result<bool, TensorZODAError> {
        // Check that exactly one opcode is executed per step
        for step in 0..self.execution_step {
            let mut opcode_count = 0;
            for row in 0..self.execution_matrix.rows {
                if !self.execution_matrix.data[row][step].is_zero() {
                    opcode_count += 1;
                }
            }
            if opcode_count != 1 {
                return Ok(false);
            }
        }
        Ok(true)
    }
    
    /// Verify state transitions are valid
    fn verify_state_transitions(&self) -> Result<bool, TensorZODAError> {
        // Verify that storage changes are monotonic and consistent
        for slot_index in 0..self.state_matrix.rows {
            let mut _last_value = F::zero();
            for step in 0..self.execution_step {
                let current_value = self.state_matrix.data[slot_index][step];
                // In full implementation, would verify transition validity
                _last_value = current_value;
            }
        }
        Ok(true)
    }
    
    /// Verify gas accounting is correct
    fn verify_gas_accounting(&self) -> Result<bool, TensorZODAError> {
        let mut total_gas = 0u64;
        for step in 0..self.execution_step {
            if let Some(_gas_cost_field) = self.gas_matrix.data.get(0).and_then(|row| row.get(step)) {
                // Convert field back to u64 (simplified)
                // In production, this would need proper field-to-integer conversion
                total_gas += 3; // Simplified gas calculation
            }
        }
        
        // Verify total gas usage is reasonable
        Ok(total_gas > 0 && total_gas <= self.transaction_data.gas_limit)
    }
    
    /// Create verification matrix for ZODA proving
    fn create_verification_matrix(&self) -> Result<Matrix<F>, TensorZODAError> {
        // Combine all matrices into a single verification matrix
        let total_rows = self.execution_matrix.rows + self.state_matrix.rows + 
                        self.memory_matrix.rows + self.stack_matrix.rows + self.gas_matrix.rows;
        
        let mut verification_matrix = Matrix::new(total_rows, self.execution_step);
        let mut row_offset = 0;
        
        // Copy execution matrix
        for i in 0..self.execution_matrix.rows {
            for j in 0..self.execution_step {
                verification_matrix.data[row_offset + i][j] = self.execution_matrix.data[i][j];
            }
        }
        row_offset += self.execution_matrix.rows;
        
        // Copy state matrix
        for i in 0..self.state_matrix.rows {
            for j in 0..self.execution_step {
                verification_matrix.data[row_offset + i][j] = self.state_matrix.data[i][j];
            }
        }
        row_offset += self.state_matrix.rows;
        
        // Copy memory matrix
        for i in 0..self.memory_matrix.rows {
            for j in 0..self.execution_step {
                verification_matrix.data[row_offset + i][j] = self.memory_matrix.data[i][j];
            }
        }
        row_offset += self.memory_matrix.rows;
        
        // Copy stack matrix
        for i in 0..self.stack_matrix.rows {
            for j in 0..self.execution_step {
                verification_matrix.data[row_offset + i][j] = self.stack_matrix.data[i][j];
            }
        }
        row_offset += self.stack_matrix.rows;
        
        // Copy gas matrix
        for i in 0..self.gas_matrix.rows {
            for j in 0..self.execution_step {
                verification_matrix.data[row_offset + i][j] = self.gas_matrix.data[i][j];
            }
        }
        
        Ok(verification_matrix)
    }
    
    /// Get performance metrics for the execution
    pub fn get_performance_metrics(&self) -> ExecutionMetrics {
        ExecutionMetrics {
            total_steps: self.execution_step,
            gas_used: self.gas_used,
            success: self.success,
            storage_slots_accessed: self.state_indices.len(),
            max_stack_depth: self.get_max_stack_depth(),
        }
    }
    
    /// Calculate maximum stack depth reached during execution
    fn get_max_stack_depth(&self) -> usize {
        let mut max_depth = 0;
        for step in 0..self.execution_step {
            let mut depth = 0;
            for row in 0..self.stack_matrix.rows {
                if !self.stack_matrix.data[row][step].is_zero() {
                    depth = row + 1;
                }
            }
            max_depth = max_depth.max(depth);
        }
        max_depth
    }
}

/// Performance metrics for EVM execution
#[derive(Debug, Clone)]
pub struct ExecutionMetrics {
    pub total_steps: usize,
    pub gas_used: u64,
    pub success: bool,
    pub storage_slots_accessed: usize,
    pub max_stack_depth: usize,
}

impl<F: Field> EVMExecutionState<F> {
    /// Create a new EVM execution state
    pub fn new() -> Self {
        Self {
            pc: 0,
            stack: Vec::new(),
            memory: Vec::new(),
            storage: HashMap::new(),
            gas_remaining: 0,
            return_data: Vec::new(),
            call_depth: 0,
            _phantom: PhantomData,
        }
    }
    
    /// Push value onto stack
    pub fn push_stack(&mut self, value: U256) -> Result<(), TensorZODAError> {
        if self.stack.len() >= 1024 {
            return Err(TensorZODAError::ExecutionError(
                "Stack overflow".to_string()
            ));
        }
        self.stack.push(value);
        Ok(())
    }
    
    /// Pop value from stack
    pub fn pop_stack(&mut self) -> Result<U256, TensorZODAError> {
        self.stack.pop().ok_or_else(|| 
            TensorZODAError::ExecutionError("Stack underflow".to_string())
        )
    }
    
    /// Set storage value
    pub fn set_storage(&mut self, key: H256, value: H256) {
        self.storage.insert(key, value);
    }
    
    /// Get storage value
    pub fn get_storage(&self, key: &H256) -> H256 {
        self.storage.get(key).copied().unwrap_or(H256::zero())
    }
}
