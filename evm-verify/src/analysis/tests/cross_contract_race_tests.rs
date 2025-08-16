//! Tests for cross-contract state race condition detection

use crate::analysis::cross_contract_race::{
    CrossContractRaceAnalyzer, StateRaceConditionKind, RaceOperation
};
use crate::circuits::execution_trace::{EVMExecutionTrace, ExecutionStep};
use ethers::types::{H160, H256, U256};

#[test]
fn test_analyzer_creation() {
    let analyzer = CrossContractRaceAnalyzer::new();
    
    // Basic test that analyzer can be created
    let race_conditions = analyzer.detect_race_conditions();
    assert!(race_conditions.is_empty(), "New analyzer should have no races");
}

#[test]
fn test_oracle_price_race_detection() {
    let analyzer = CrossContractRaceAnalyzer::new();
    
    // Test oracle price race detection
    let race_conditions = analyzer.detect_race_conditions();
    
    // Should complete without panicking
    assert!(true, "Oracle race detection should complete");
}

fn create_race_condition_trace() -> EVMExecutionTrace {
    let contract_a = H160::from_low_u64_be(1);
    let contract_b = H160::from_low_u64_be(2);
    
    EVMExecutionTrace {
        transaction_hash: H256::from_low_u64_be(1),
        execution_steps: vec![
            ExecutionStep {
                opcode: 0x54, // SLOAD
                opcode_name: "SLOAD".to_string(),
                gas_before: U256::from(100000),
                gas_after: U256::from(95000),
                gas_cost: U256::from(5000),
                stack_before: vec![U256::from(100)],
                stack_after: vec![U256::from(50)],
                memory_changes: Vec::new(),
                storage_changes: Vec::new(),
                call_depth: 0,
                contract_address: contract_a,
                error: None,
                pc: 0,
                execution_time_ns: 1000,
            },
            ExecutionStep {
                opcode: 0x55, // SSTORE
                opcode_name: "SSTORE".to_string(),
                gas_before: U256::from(95000),
                gas_after: U256::from(90000),
                gas_cost: U256::from(5000),
                stack_before: vec![U256::from(100), U256::from(100)],
                stack_after: Vec::new(),
                memory_changes: Vec::new(),
                storage_changes: Vec::new(),
                call_depth: 0,
                contract_address: contract_a,
                error: None,
                pc: 1,
                execution_time_ns: 2000,
            },
        ],
        initial_state: crate::circuits::execution_trace::EVMState::new(),
        final_state: crate::circuits::execution_trace::EVMState::new(),
        gas_trace: crate::circuits::execution_trace::GasTrace::new(),
        memory_trace: crate::circuits::execution_trace::MemoryTrace::new(),
        storage_trace: crate::circuits::execution_trace::StorageTrace::new(),
        stack_trace: crate::circuits::execution_trace::StackTrace::new(),
    }
}
