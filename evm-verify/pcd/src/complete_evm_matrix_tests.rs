//! Unit tests for the complete EVM execution matrix
//! 
//! This module tests the core functionality of the CompleteEVMExecutionMatrix
//! for proving complete EVM state transitions using tensor operations.



#[cfg(test)]
mod tests {
    use crate::complete_evm_matrix::{
        CompleteEVMExecutionMatrix, EVMExecutionState, EVMOpcode, TransactionData
    };
    use crate::tensor_zoda::TensorZODAError;
    use ark_bn254::Fr as TestField;
    use ark_ff::Zero;
    use ethers::types::{Address, U256, H256};
    use std::str::FromStr;

    /// Test creating a new CompleteEVMExecutionMatrix
    #[test]
    fn test_complete_evm_matrix_creation() {
        // Create test bytecode (simple ADD operation)
        let bytecode = vec![0x60, 0x01, 0x60, 0x02, 0x01]; // PUSH1 1, PUSH1 2, ADD
        
        // Create transaction data
        let transaction_data = TransactionData {
            from: Address::from_str("0x742d35cc6a4c6B89Bf3F44a9bD02C8E7DC7B0b00").unwrap(),
            to: Some(Address::from_str("0x742d35cc6a4c6B89Bf3F44a9bD02C8E7DC7B0b01").unwrap()),
            value: U256::from(1000),
            gas_limit: 21000,
            gas_price: U256::from(20_000_000_000u64), // 20 gwei
            nonce: 1,
            data: bytecode.clone(),
            chain_id: Some(1), // Ethereum mainnet
        };
        
        // Create matrix with max 100 steps
        let result = CompleteEVMExecutionMatrix::<TestField>::new(
            bytecode,
            transaction_data,
            100
        );
        
        assert!(result.is_ok());
        let matrix = result.unwrap();
        
        // Verify initialization
        assert_eq!(matrix.max_steps, 100);
        assert_eq!(matrix.execution_step, 0);
        assert_eq!(matrix.gas_used, 0);
        assert!(!matrix.success);
        assert_eq!(matrix.return_data.len(), 0);
        
        // Verify matrix dimensions
        assert_eq!(matrix.execution_matrix.rows, 256); // All possible opcodes
        assert_eq!(matrix.execution_matrix.cols, 100); // Max steps
        assert_eq!(matrix.state_matrix.rows, 1024);    // Storage slots
        assert_eq!(matrix.stack_matrix.rows, 1024);    // Stack depth
        assert_eq!(matrix.gas_matrix.rows, 16);        // Gas metrics
    }
    
    /// Test encoding a simple execution step
    #[test]
    fn test_encode_execution_step() {
        let bytecode = vec![0x01]; // ADD opcode
        let transaction_data = TransactionData {
            from: Address::from_str("0x742d35cc6a4c6B89Bf3F44a9bD02C8E7DC7B0b00").unwrap(),
            to: Some(Address::from_str("0x742d35cc6a4c6B89Bf3F44a9bD02C8E7DC7B0b01").unwrap()),
            value: U256::from(1000),
            gas_limit: 21000,
            gas_price: U256::from(20_000_000_000u64),
            nonce: 1,
            data: bytecode.clone(),
            chain_id: Some(1), // Ethereum mainnet
        };
        
        let mut matrix = CompleteEVMExecutionMatrix::<TestField>::new(
            bytecode,
            transaction_data,
            10
        ).unwrap();
        
        // Create execution state
        let mut execution_state = EVMExecutionState::<TestField>::new();
        execution_state.gas_remaining = 21000;
        execution_state.pc = 0;
        execution_state.call_depth = 0;
        
        // Add some stack values
        execution_state.push_stack(U256::from(1)).unwrap();
        execution_state.push_stack(U256::from(2)).unwrap();
        
        // Add storage state
        let storage_key = H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let storage_value = H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000042").unwrap();
        execution_state.set_storage(storage_key, storage_value);
        
        // Encode ADD operation
        let result = matrix.encode_execution_step(
            EVMOpcode::ADD,
            &execution_state,
            3 // Gas cost for ADD
        );
        
        assert!(result.is_ok());
        assert_eq!(matrix.execution_step, 1);
        
        // Verify opcode was encoded correctly
        assert!(!matrix.execution_matrix.data[EVMOpcode::ADD as u8 as usize][0].is_zero());
        
        // Verify gas information was encoded
        assert_eq!(matrix.gas_matrix.data[0][0], TestField::from(3u64)); // Gas cost
        assert_eq!(matrix.gas_matrix.data[1][0], TestField::from(21000u64)); // Remaining gas
        assert_eq!(matrix.gas_matrix.data[2][0], TestField::from(0u64)); // PC
        assert_eq!(matrix.gas_matrix.data[3][0], TestField::from(0u64)); // Call depth
    }
    
    /// Test EVMExecutionState stack operations
    #[test]
    fn test_execution_state_stack_operations() {
        let mut state = EVMExecutionState::<TestField>::new();
        
        // Test push operations
        assert!(state.push_stack(U256::from(42)).is_ok());
        assert!(state.push_stack(U256::from(100)).is_ok());
        assert_eq!(state.stack.len(), 2);
        
        // Test pop operations
        let value = state.pop_stack().unwrap();
        assert_eq!(value, U256::from(100));
        assert_eq!(state.stack.len(), 1);
        
        let value = state.pop_stack().unwrap();
        assert_eq!(value, U256::from(42));
        assert_eq!(state.stack.len(), 0);
        
        // Test stack underflow
        let result = state.pop_stack();
        assert!(result.is_err());
    }
    
    /// Test EVMExecutionState storage operations
    #[test]
    fn test_execution_state_storage_operations() {
        let mut state = EVMExecutionState::<TestField>::new();
        
        let key1 = H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let value1 = H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000042").unwrap();
        
        let key2 = H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000002").unwrap();
        let value2 = H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000100").unwrap();
        
        // Test storage setting
        state.set_storage(key1, value1);
        state.set_storage(key2, value2);
        
        // Test storage getting
        assert_eq!(state.get_storage(&key1), value1);
        assert_eq!(state.get_storage(&key2), value2);
        
        // Test non-existent key
        let key3 = H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000003").unwrap();
        assert_eq!(state.get_storage(&key3), H256::zero());
    }
    
    /// Test EVMOpcode gas cost calculations
    #[test]
    fn test_opcode_gas_costs() {
        // Test arithmetic operations
        assert_eq!(EVMOpcode::ADD.gas_cost(), 3);
        assert_eq!(EVMOpcode::MUL.gas_cost(), 3);
        assert_eq!(EVMOpcode::DIV.gas_cost(), 5);
        assert_eq!(EVMOpcode::EXP.gas_cost(), 10);
        
        // Test memory operations
        assert_eq!(EVMOpcode::MLOAD.gas_cost(), 3);
        assert_eq!(EVMOpcode::MSTORE.gas_cost(), 3);
        assert_eq!(EVMOpcode::SLOAD.gas_cost(), 100);
        assert_eq!(EVMOpcode::SSTORE.gas_cost(), 100);
        
        // Test control flow
        assert_eq!(EVMOpcode::JUMP.gas_cost(), 8);
        assert_eq!(EVMOpcode::JUMPI.gas_cost(), 10);
        assert_eq!(EVMOpcode::JUMPDEST.gas_cost(), 1);
        
        // Test push operations
        assert_eq!(EVMOpcode::PUSH1.gas_cost(), 3);
        assert_eq!(EVMOpcode::PUSH32.gas_cost(), 3);
        
        // Test stack operations
        assert_eq!(EVMOpcode::DUP1.gas_cost(), 3);
        assert_eq!(EVMOpcode::SWAP1.gas_cost(), 3);
        
        // Test system operations
        assert_eq!(EVMOpcode::CREATE.gas_cost(), 32000);
        assert_eq!(EVMOpcode::CALL.gas_cost(), 100);
    }
    
    /// Test opcode state modification checks
    #[test]
    fn test_opcode_state_modification() {
        // State-modifying opcodes
        assert!(EVMOpcode::SSTORE.modifies_state());
        assert!(EVMOpcode::CREATE.modifies_state());
        assert!(EVMOpcode::CREATE2.modifies_state());
        assert!(EVMOpcode::CALL.modifies_state());
        assert!(EVMOpcode::LOG0.modifies_state());
        assert!(EVMOpcode::SELFDESTRUCT.modifies_state());
        
        // Non-state-modifying opcodes
        assert!(!EVMOpcode::ADD.modifies_state());
        assert!(!EVMOpcode::PUSH1.modifies_state());
        assert!(!EVMOpcode::MLOAD.modifies_state());
        assert!(!EVMOpcode::JUMP.modifies_state());
    }
    
    /// Test opcode halt conditions
    #[test]
    fn test_opcode_halt_conditions() {
        // Halting opcodes
        assert!(EVMOpcode::STOP.can_halt());
        assert!(EVMOpcode::RETURN.can_halt());
        assert!(EVMOpcode::REVERT.can_halt());
        assert!(EVMOpcode::INVALID.can_halt());
        assert!(EVMOpcode::SELFDESTRUCT.can_halt());
        
        // Non-halting opcodes
        assert!(!EVMOpcode::ADD.can_halt());
        assert!(!EVMOpcode::PUSH1.can_halt());
        assert!(!EVMOpcode::JUMP.can_halt());
        assert!(!EVMOpcode::CALL.can_halt());
    }
    
    /// Test finalization of execution
    #[test]
    fn test_finalize_execution() {
        let bytecode = vec![0x00]; // STOP
        let transaction_data = TransactionData {
            from: Address::from_str("0x742d35cc6a4c6B89Bf3F44a9bD02C8E7DC7B0b00").unwrap(),
            to: Some(Address::from_str("0x742d35cc6a4c6B89Bf3F44a9bD02C8E7DC7B0b01").unwrap()),
            value: U256::from(0),
            gas_limit: 21000,
            gas_price: U256::from(20_000_000_000u64),
            nonce: 1,
            data: bytecode.clone(),
            chain_id: Some(1), // Ethereum mainnet
        };
        
        let mut matrix = CompleteEVMExecutionMatrix::<TestField>::new(
            bytecode,
            transaction_data,
            10
        ).unwrap();
        
        let final_state_root = H256::from_str("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
        let return_data = vec![0x42, 0x43, 0x44];
        
        matrix.finalize_execution(
            final_state_root,
            21000,
            true,
            return_data.clone()
        );
        
        assert_eq!(matrix.final_state_root, final_state_root);
        assert_eq!(matrix.gas_used, 21000);
        assert!(matrix.success);
        assert_eq!(matrix.return_data, return_data);
    }
    
    /// Test execution step limit
    #[test]
    fn test_execution_step_limit() {
        let bytecode = vec![0x01]; // ADD
        let transaction_data = TransactionData {
            from: Address::from_str("0x742d35cc6a4c6B89Bf3F44a9bD02C8E7DC7B0b00").unwrap(),
            to: Some(Address::from_str("0x742d35cc6a4c6B89Bf3F44a9bD02C8E7DC7B0b01").unwrap()),
            value: U256::from(0),
            gas_limit: 21000,
            gas_price: U256::from(20_000_000_000u64),
            nonce: 1,
            data: bytecode.clone(),
            chain_id: Some(1), // Ethereum mainnet
        };
        
        // Create matrix with only 1 step allowed
        let mut matrix = CompleteEVMExecutionMatrix::<TestField>::new(
            bytecode,
            transaction_data,
            1
        ).unwrap();
        
        let execution_state = EVMExecutionState::<TestField>::new();
        
        // First step should succeed
        let result = matrix.encode_execution_step(EVMOpcode::ADD, &execution_state, 3);
        assert!(result.is_ok());
        assert_eq!(matrix.execution_step, 1);
        
        // Second step should fail due to limit
        let result = matrix.encode_execution_step(EVMOpcode::MUL, &execution_state, 3);
        assert!(result.is_err());
        if let Err(TensorZODAError::MatrixDimensionMismatch(_)) = result {
            // Expected error type
        } else {
            panic!("Expected MatrixDimensionMismatch error");
        }
    }
    
    /// Test performance metrics calculation
    #[test]
    fn test_performance_metrics() {
        let bytecode = vec![0x01, 0x02, 0x00]; // ADD, MUL, STOP
        let transaction_data = TransactionData {
            from: Address::from_str("0x742d35cc6a4c6B89Bf3F44a9bD02C8E7DC7B0b00").unwrap(),
            to: Some(Address::from_str("0x742d35cc6a4c6B89Bf3F44a9bD02C8E7DC7B0b01").unwrap()),
            value: U256::from(0),
            gas_limit: 21000,
            gas_price: U256::from(20_000_000_000u64),
            nonce: 1,
            data: bytecode.clone(),
            chain_id: Some(1), // Ethereum mainnet
        };
        
        let mut matrix = CompleteEVMExecutionMatrix::<TestField>::new(
            bytecode,
            transaction_data,
            10
        ).unwrap();
        
        // Execute a few steps
        let mut execution_state = EVMExecutionState::<TestField>::new();
        execution_state.push_stack(U256::from(1)).unwrap();
        execution_state.push_stack(U256::from(2)).unwrap();
        
        matrix.encode_execution_step(EVMOpcode::ADD, &execution_state, 3).unwrap();
        matrix.encode_execution_step(EVMOpcode::MUL, &execution_state, 3).unwrap();
        
        // Finalize execution
        matrix.finalize_execution(H256::zero(), 6, true, vec![]);
        
        // Get performance metrics
        let metrics = matrix.get_performance_metrics();
        
        assert_eq!(metrics.total_steps, 2);
        assert_eq!(metrics.gas_used, 6);
        assert!(metrics.success);
        assert_eq!(metrics.storage_slots_accessed, 0);
        assert!(metrics.max_stack_depth > 0);
    }
}
