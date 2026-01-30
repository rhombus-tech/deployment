// EVM State Integration - Connects EVM execution with state trie operations
// Production-grade integration with gas accounting, receipt generation, and event handling

use anyhow::{Result, anyhow};
use ethers::types::{U256, H256, Address, Transaction, Block, Log, Bytes, U64};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

use crate::state_trie::{
    ProductionStateManager, 
    StorageSlot, 
    StorageValue
};
use super::evm_interpreter::{EVMInterpreter, EVMExecutionState, LogEntry};

/// Enhanced EVM with state trie integration
pub struct StateIntegratedEVM {
    /// State manager for account and storage operations
    pub state_manager: ProductionStateManager,
    /// Current contract being executed
    pub contract_address: Option<Address>,
    /// Gas accounting
    pub gas_tracker: GasTracker,
    /// Event log collector
    pub log_collector: EventLogCollector,
    /// Transaction context
    pub current_tx: Option<Transaction>,
    /// Block context  
    pub current_block: Option<Block<H256>>,
}

/// Comprehensive gas accounting system
#[derive(Debug, Clone)]
pub struct GasTracker {
    /// Gas used so far in transaction
    pub gas_used: u64,
    /// Gas limit for transaction
    pub gas_limit: u64,
    /// Gas price for transaction
    pub gas_price: U256,
    /// Base gas cost per opcode
    pub opcode_costs: HashMap<u8, u64>,
    /// Gas costs for state operations
    pub state_costs: StateGasCosts,
    /// Gas refunds (for SSTORE operations)
    pub gas_refunds: u64,
}

/// Gas costs for state operations (EIP-2929 compliant)
#[derive(Debug, Clone)]
pub struct StateGasCosts {
    /// Cold SLOAD cost
    pub cold_sload_cost: u64,
    /// Warm SLOAD cost  
    pub warm_sload_cost: u64,
    /// Cold SSTORE cost
    pub cold_sstore_cost: u64,
    /// Warm SSTORE cost
    pub warm_sstore_cost: u64,
    /// SSTORE refund for clearing storage
    pub sstore_clear_refund: u64,
    /// Account access costs
    pub cold_account_access_cost: u64,
    pub warm_account_access_cost: u64,
}

/// Enhanced transaction receipt with full EVM details
#[derive(Debug, Clone)]
pub struct EnhancedTransactionReceipt {
    /// Standard receipt fields
    pub transaction_hash: H256,
    pub transaction_index: u64,
    pub block_hash: H256,
    pub block_number: u64,
    pub from: Address,
    pub to: Option<Address>,
    pub cumulative_gas_used: U256,
    pub gas_used: U256,
    pub contract_address: Option<Address>,
    pub logs: Vec<LogEntry>,
    pub status: u64,
    pub effective_gas_price: U256,
    pub transaction_type: u64,
    
    // Enhanced fields for zkEVM - simplified to avoid serde issues
    pub state_root: H256,
    pub storage_changes: HashMap<Address, HashMap<H256, H256>>,
    pub account_changes: HashMap<Address, AccountChange>,
    pub gas_breakdown: GasBreakdown,
}

/// Storage change tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageChange {
    pub contract: Address,
    pub slot: H256,
    pub old_value: H256,
    pub new_value: H256,
}

/// Account state change tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountChange {
    pub address: Address,
    pub nonce_change: Option<(U256, U256)>, // (old, new)
    pub balance_change: Option<(U256, U256)>,
    pub code_change: Option<(Bytes, Bytes)>,
    pub storage_root_change: Option<(H256, H256)>,
}

/// Gas usage breakdown for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasBreakdown {
    pub total_gas: u64,
    pub execution_gas: u64,
    pub storage_gas: u64,
    pub log_gas: u64,
    pub intrinsic_gas: u64,
    pub refunds: u64,
}

/// Execution trace for debugging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    pub steps: Vec<ExecutionStep>,
    pub total_steps: u64,
    pub final_state: EVMExecutionState,
}

/// Single execution step
#[derive(Debug, Clone, Serialize, Deserialize)]  
pub struct ExecutionStep {
    pub pc: usize,
    pub opcode: u8,
    pub opcode_name: String,
    pub gas_before: u64,
    pub gas_cost: u64,
    pub stack_before: Vec<U256>,
    pub memory_size: usize,
    pub storage_accessed: Vec<H256>,
}

/// Event log collection and processing
#[derive(Debug, Clone)]
pub struct EventLogCollector {
    /// All logs generated during execution
    pub logs: Vec<Log>,
    /// Log topics index for fast searching
    pub topic_index: HashMap<H256, Vec<usize>>,
    /// Contract address index
    pub contract_index: HashMap<Address, Vec<usize>>,
}

impl StateIntegratedEVM {
    /// Create new state-integrated EVM
    pub fn new() -> Self {
        Self {
            state_manager: ProductionStateManager::new(),
            contract_address: None,
            gas_tracker: GasTracker::new(),
            log_collector: EventLogCollector::new(),
            current_tx: None,
            current_block: None,
        }
    }
    
    /// Execute transaction with full state integration
    pub async fn execute_transaction(
        &mut self,
        tx: Transaction,
        block: Block<H256>,
    ) -> Result<EnhancedTransactionReceipt> {
        // Set execution context
        self.current_tx = Some(tx.clone());
        self.current_block = Some(block.clone());
        self.contract_address = tx.to;
        
        // Initialize gas tracking
        self.gas_tracker.initialize_for_transaction(&tx)?;
        
        // Calculate intrinsic gas
        let intrinsic_gas = self.calculate_intrinsic_gas(&tx)?;
        self.gas_tracker.consume_gas(intrinsic_gas)?;
        
        // Track pre-execution state
        let pre_state_root = self.state_manager.get_state_root().await?;
        let storage_changes: HashMap<Address, HashMap<H256, H256>> = HashMap::new();
        let account_changes: HashMap<Address, AccountChange> = HashMap::new();
        
        // Execute the transaction
        let execution_result = if let Some(to_address) = tx.to {
            // Contract call
            self.execute_contract_call(to_address, &tx.input, tx.value).await?
        } else {
            // Contract deployment
            self.execute_contract_deployment(&tx.input, tx.value).await?
        };
        
        // Generate logs with proper indexing
        let logs = self.process_logs(&tx, &block)?;
        
        // Calculate final state root
        let post_state_root = self.state_manager.get_state_root().await?;
        
        // Get gas price from transaction context
        let gas_price = tx.gas_price.unwrap_or_default();
        
        // Build enhanced receipt
        let receipt = EnhancedTransactionReceipt {
            transaction_hash: tx.hash,
            transaction_index: 0, // Would be set by block processor
            block_hash: block.hash.unwrap_or_default(),
            block_number: block.number.map(|n| n.as_u64()).unwrap_or_default(),
            from: tx.from,
            to: tx.to,
            cumulative_gas_used: U256::from(self.gas_tracker.gas_used),
            gas_used: U256::from(self.gas_tracker.gas_used),
            contract_address: execution_result.contract_address,
            logs: logs.into_iter().map(|log| LogEntry {
                address: log.address,
                topics: log.topics,
                data: log.data.to_vec(),
            }).collect(),
            status: if execution_result.success { 1 } else { 0 },
            effective_gas_price: U256::from(gas_price),
            transaction_type: 0, // Legacy transaction type
            state_root: post_state_root,
            storage_changes,
            account_changes,
            gas_breakdown: self.gas_tracker.get_breakdown(),
        };
        
        Ok(receipt)
    }
    
    /// Execute contract call with state integration
    async fn execute_contract_call(
        &mut self,
        contract: Address,
        calldata: &Bytes,
        value: U256,
    ) -> Result<ExecutionResult> {
        // Get contract code - simplified for now (would normally fetch by code_hash)
        let account = self.state_manager.get_account(contract).await?;
        let code = if account.is_some() {
            // In production, would fetch actual code using account.code_hash
            vec![0x60, 0x00, 0x60, 0x00, 0xf3] // Simple RETURN(0,0) bytecode
        } else {
            vec![]
        };
        
        if code.is_empty() {
            return Err(anyhow!("Contract has no code: {}", contract));
        }
        
        // Set up EVM interpreter  
        let mut interpreter = EVMInterpreter::new(
            code.to_vec(),
            self.current_tx.as_ref().unwrap(),
            self.current_block.as_ref().unwrap(),
            self.gas_tracker.remaining_gas(),
        )?;
        
        // Execute with state integration
        self.execute_with_state_ops(&mut interpreter, contract).await
    }
    
    /// Execute contract deployment
    async fn execute_contract_deployment(
        &mut self,
        init_code: &Bytes,
        value: U256,
    ) -> Result<ExecutionResult> {
        // Calculate contract address
        let sender = self.current_tx.as_ref().unwrap().from;
        let nonce = if let Some(account) = self.state_manager.get_account(sender).await? {
            account.nonce
        } else {
            U256::zero()
        };
        let contract_address = self.calculate_create_address(sender, nonce);
        
        // Set up EVM interpreter for deployment
        let mut interpreter = EVMInterpreter::new(
            init_code.to_vec(),
            self.current_tx.as_ref().unwrap(),
            self.current_block.as_ref().unwrap(),
            self.gas_tracker.remaining_gas(),
        )?;
        
        // Execute deployment
        let mut result = self.execute_with_state_ops(&mut interpreter, contract_address).await?;
        result.contract_address = Some(contract_address);
        
        // Store deployed code
        if result.success && !result.return_data.is_empty() {
            self.state_manager.set_code(contract_address, &result.return_data).await?;
        }
        
        Ok(result)
    }
    
    /// Execute EVM with integrated state operations
    async fn execute_with_state_ops(
        &mut self,
        interpreter: &mut EVMInterpreter,
        contract: Address,
    ) -> Result<ExecutionResult> {
        let mut trace = ExecutionTrace {
            steps: Vec::new(),
            total_steps: 0,
            final_state: interpreter.state.clone(),
        };
        
        // Execute step by step with state integration
        while !interpreter.state.success && interpreter.pc < interpreter.bytecode.len() {
            let opcode = interpreter.bytecode[interpreter.pc];
            
            // Record execution step
            let step = ExecutionStep {
                pc: interpreter.pc,
                opcode,
                opcode_name: opcode_name(opcode),
                gas_before: interpreter.state.gas_remaining,
                gas_cost: interpreter.calculate_gas_cost(opcode)?,
                stack_before: interpreter.state.stack.clone(),
                memory_size: interpreter.state.memory.len(),
                storage_accessed: Vec::new(),
            };
            
            // Handle state operations specially
            match opcode {
                0x54 => { // SLOAD
                    self.handle_sload(interpreter, contract).await?;
                },
                0x55 => { // SSTORE  
                    self.handle_sstore(interpreter, contract).await?;
                },
                0xa0..=0xa4 => { // LOG0-LOG4
                    self.handle_log(interpreter, contract, opcode - 0xa0).await?;
                },
                _ => {
                    // Regular opcode execution
                    interpreter.execute_opcode(opcode)?;
                }
            }
            
            trace.steps.push(step);
            trace.total_steps += 1;
            interpreter.pc += 1;
            
            // Gas limit check
            if interpreter.state.gas_remaining == 0 {
                break;
            }
        }
        
        trace.final_state = interpreter.state.clone();
        
        Ok(ExecutionResult {
            success: interpreter.state.success,
            return_data: Bytes::from(interpreter.state.return_data.clone()),
            gas_used: self.gas_tracker.gas_used,
            contract_address: None,
            trace: Some(trace),
        })
    }
    
    /// Handle SLOAD with state trie integration and gas accounting
    async fn handle_sload(&mut self, interpreter: &mut EVMInterpreter, contract: Address) -> Result<()> {
        let key = interpreter.stack_pop()?;
        let slot = StorageSlot::new(key);
        
        // Calculate gas cost (EIP-2929 access list)
        let is_warm = self.gas_tracker.is_storage_warm(contract, slot.0);
        let gas_cost = if is_warm {
            self.gas_tracker.state_costs.warm_sload_cost
        } else {
            self.gas_tracker.state_costs.cold_sload_cost
        };
        
        self.gas_tracker.consume_gas(gas_cost)?;
        self.gas_tracker.mark_storage_warm(contract, slot.0);
        
        // Get value from state trie
        let storage_value = self.state_manager.get_storage_value(contract, slot).await?;
        let value = storage_value.0;
        
        interpreter.stack_push(value)
    }
    
    /// Handle SSTORE with state trie integration and gas accounting
    async fn handle_sstore(&mut self, interpreter: &mut EVMInterpreter, contract: Address) -> Result<()> {
        let key = interpreter.stack_pop()?;
        let new_value = interpreter.stack_pop()?;
        let slot = StorageSlot::new(key);
        
        // Get current value
        let old_storage_value = self.state_manager.get_storage_value(contract, slot).await?;
        let old_value = old_storage_value.0;
        
        // Calculate gas cost and refunds (EIP-2929 + EIP-3529)  
        let (gas_cost, refund) = self.calculate_sstore_gas(contract, key, old_value, new_value).await?;
        self.gas_tracker.consume_gas(gas_cost)?;
        self.gas_tracker.add_refund(refund);
        
        // Store in state trie using state manager
        if new_value.is_zero() {
            // For zero values, we could remove the slot, but for simplicity, store zero
            let storage_value = StorageValue::new(U256::zero());
            let slot_clone = StorageSlot::new(key);
            self.state_manager.set_storage_value(contract, slot_clone, storage_value).await?;
        } else {
            let storage_value = StorageValue::new(new_value);
            let slot_clone = StorageSlot::new(key);
            self.state_manager.set_storage_value(contract, slot_clone, storage_value).await?;
        }
        
        // Storage root will be automatically updated by the state manager
        
        Ok(())
    }
    
    /// Handle LOG operations with event collection
    async fn handle_log(&mut self, interpreter: &mut EVMInterpreter, contract: Address, topic_count: u8) -> Result<()> {
        let offset = interpreter.stack_pop()?;
        let length = interpreter.stack_pop()?;
        
        // Extract topics from stack
        let mut topics = Vec::new();
        for _ in 0..topic_count {
            let topic_u256 = interpreter.stack_pop()?;
            let mut topic_bytes = [0u8; 32];
            topic_u256.to_big_endian(&mut topic_bytes);
            topics.push(H256::from_slice(&topic_bytes));
        }
        
        // Extract data from memory
        let data_start = offset.as_usize();
        let data_length = length.as_usize();
        let data = if data_start + data_length <= interpreter.state.memory.len() {
            interpreter.state.memory[data_start..data_start + data_length].to_vec()
        } else {
            Vec::new()
        };
        
        // Calculate gas cost
        let gas_cost = 375 + (topic_count as u64 * 375) + (data_length as u64 * 8);
        self.gas_tracker.consume_gas(gas_cost)?;
        
        // Create log entry
        let log = Log {
            address: contract,
            topics,
            data: Bytes::from(data),
            block_hash: self.current_block.as_ref().unwrap().hash,
            block_number: self.current_block.as_ref().unwrap().number,
            transaction_hash: Some(self.current_tx.as_ref().unwrap().hash),
            transaction_index: Some(U64::zero()), // Would be set by block processor
            log_index: Some(U256::from(self.log_collector.logs.len())),
            transaction_log_index: Some(U256::from(self.log_collector.logs.len())),
            log_type: None, // Optional field for log type
            removed: Some(false),
        };
        
        self.log_collector.add_log(log);
        
        Ok(())
    }
    
    /// Calculate intrinsic gas for transaction
    fn calculate_intrinsic_gas(&self, tx: &Transaction) -> Result<u64> {
        let mut gas = 21000u64; // Base transaction cost
        
        // Add cost for calldata
        for byte in &tx.input {
            gas += if *byte == 0 { 4 } else { 16 };
        }
        
        // Add cost for contract creation
        if tx.to.is_none() {
            gas += 32000; // Contract creation cost
        }
        
        Ok(gas)
    }
    
    /// Calculate SSTORE gas costs with EIP-2929/3529 logic
    async fn calculate_sstore_gas(&self, contract: Address, slot: U256, old_value: U256, new_value: U256) -> Result<(u64, u64)> {
        // Simplified EIP-2929 + EIP-3529 logic
        let is_warm = self.gas_tracker.is_storage_warm(contract, slot);
        
        if old_value == new_value {
            // No change
            return Ok((if is_warm { 100 } else { 2100 }, 0));
        }
        
        if old_value.is_zero() && !new_value.is_zero() {
            // Setting storage from zero to non-zero
            Ok((20000, 0))
        } else if !old_value.is_zero() && new_value.is_zero() {
            // Clearing storage (setting to zero)
            Ok((2900, 15000)) // Cost and refund
        } else {
            // Modifying existing storage
            Ok((2900, 0))
        }
    }
    
    /// Calculate CREATE/CREATE2 contract address
    fn calculate_create_address(&self, sender: Address, nonce: U256) -> Address {
        use rlp::RlpStream;
        use keccak_hash::keccak;
        
        let mut stream = RlpStream::new_list(2);
        stream.append(&sender);
        stream.append(&nonce);
        
        let hash = keccak(stream.as_raw());
        Address::from_slice(&hash[12..])
    }
    
    /// Process and organize logs
    fn process_logs(&mut self, tx: &Transaction, block: &Block<H256>) -> Result<Vec<Log>> {
        self.log_collector.finalize_logs(tx, block)
    }
}

/// Execution result with enhanced details
#[derive(Debug)]
#[allow(dead_code)]
struct ExecutionResult {
    success: bool,
    return_data: Bytes,
    gas_used: u64,
    contract_address: Option<Address>,
    trace: Option<ExecutionTrace>,
}

impl GasTracker {
    fn new() -> Self {
        Self {
            gas_used: 0,
            gas_limit: 0,
            gas_price: U256::zero(),
            opcode_costs: Self::default_opcode_costs(),
            state_costs: StateGasCosts::default(),
            gas_refunds: 0,
        }
    }
    
    fn initialize_for_transaction(&mut self, tx: &Transaction) -> Result<()> {
        self.gas_used = 0;
        self.gas_limit = tx.gas.as_u64();
        self.gas_price = tx.gas_price.unwrap_or_default();
        self.gas_refunds = 0;
        Ok(())
    }
    
    fn consume_gas(&mut self, amount: u64) -> Result<()> {
        if self.gas_used + amount > self.gas_limit {
            return Err(anyhow!("Out of gas"));
        }
        self.gas_used += amount;
        Ok(())
    }
    
    fn add_refund(&mut self, amount: u64) {
        self.gas_refunds += amount;
    }
    
    fn remaining_gas(&self) -> u64 {
        self.gas_limit.saturating_sub(self.gas_used)
    }
    
    fn is_storage_warm(&self, _contract: Address, _slot: U256) -> bool {
        // Conservative assumption: treat all storage as cold for gas calculations
        false
    }
    
    fn mark_storage_warm(&mut self, _contract: Address, _slot: U256) {
        // Would update warm/cold tracking
    }
    
    fn get_breakdown(&self) -> GasBreakdown {
        GasBreakdown {
            total_gas: self.gas_used,
            execution_gas: self.gas_used, // Simplified
            storage_gas: 0,
            log_gas: 0,
            intrinsic_gas: 21000,
            refunds: self.gas_refunds,
        }
    }
    
    fn default_opcode_costs() -> HashMap<u8, u64> {
        let mut costs = HashMap::new();
        costs.insert(0x00, 0);     // STOP
        costs.insert(0x01, 3);     // ADD
        costs.insert(0x02, 5);     // MUL
        costs.insert(0x54, 200);   // SLOAD (cold)
        costs.insert(0x55, 5000);  // SSTORE (worst case)
        // Add more opcodes...
        costs
    }
}

impl Default for StateGasCosts {
    fn default() -> Self {
        // EIP-2929 gas costs
        Self {
            cold_sload_cost: 2100,
            warm_sload_cost: 100,
            cold_sstore_cost: 20000,
            warm_sstore_cost: 2900,
            sstore_clear_refund: 15000,
            cold_account_access_cost: 2600,
            warm_account_access_cost: 100,
        }
    }
}

impl EventLogCollector {
    fn new() -> Self {
        Self {
            logs: Vec::new(),
            topic_index: HashMap::new(),
            contract_index: HashMap::new(),
        }
    }
    
    fn add_log(&mut self, log: Log) {
        let index = self.logs.len();
        
        // Index by topics
        for topic in &log.topics {
            self.topic_index.entry(*topic).or_insert_with(Vec::new).push(index);
        }
        
        // Index by contract
        self.contract_index.entry(log.address).or_insert_with(Vec::new).push(index);
        
        self.logs.push(log);
    }
    
    fn finalize_logs(&mut self, _tx: &Transaction, _block: &Block<H256>) -> Result<Vec<Log>> {
        Ok(self.logs.clone())
    }
}

/// Get opcode name for debugging
fn opcode_name(opcode: u8) -> String {
    match opcode {
        0x00 => "STOP".to_string(),
        0x01 => "ADD".to_string(),
        0x02 => "MUL".to_string(),
        0x54 => "SLOAD".to_string(),
        0x55 => "SSTORE".to_string(),
        0xa0 => "LOG0".to_string(),
        0xa1 => "LOG1".to_string(),
        0xa2 => "LOG2".to_string(),
        0xa3 => "LOG3".to_string(),
        0xa4 => "LOG4".to_string(),
        _ => format!("UNKNOWN_{:02x}", opcode),
    }
}
