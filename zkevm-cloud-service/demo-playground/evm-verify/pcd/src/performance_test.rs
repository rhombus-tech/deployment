//! Performance testing for CompleteEVMExecutionMatrix
use std::time::Instant;
use ethers::types::{Address, U256};
use ark_bls12_381::Fr as TestField;
use crate::complete_evm_matrix::{CompleteEVMExecutionMatrix, TransactionData, ExecutionMetrics};

/// Comprehensive performance benchmarking for CompleteEVMExecutionMatrix
pub fn run_performance_benchmarks() {
    println!("🚀 CompleteEVMExecutionMatrix Performance Benchmarks");
    println!("{}", "=".repeat(60));
    
    // Test different contract sizes
    let test_sizes = vec![
        ("Tiny Contract", vec![0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3]), // 10 bytes
        ("Small Contract", generate_bytecode(100)),  // 100 bytes
        ("Medium Contract", generate_bytecode(1000)), // 1KB
        ("Large Contract", generate_bytecode(4000)),  // 4KB
    ];
    
    for (name, bytecode) in test_sizes {
        println!("\n📊 Testing: {}", name);
        benchmark_contract_execution(&bytecode, name);
    }
    
    // Test different execution complexities
    println!("\n📈 Execution Complexity Tests");
    benchmark_opcode_types();
    
    // Test matrix operations
    println!("\n🔢 Matrix Operations Benchmarks"); 
    benchmark_matrix_operations();
}

fn benchmark_contract_execution(bytecode: &[u8], _name: &str) {
    let iterations = 10;
    let mut total_time = std::time::Duration::ZERO;
    let mut metrics_vec = Vec::new();
    
    for i in 0..iterations {
        let start = Instant::now();
        
        let tx_data = TransactionData {
            from: Address::zero(),
            to: Some(Address::zero()),
            value: U256::from(1000u64),
            gas_limit: 100000,
            gas_price: U256::from(20_000_000_000u64),
            data: bytecode.to_vec(),
            nonce: 0,
            chain_id: Some(1),
        };
        
        // Create matrix with proper parameters
        let matrix = CompleteEVMExecutionMatrix::<TestField>::new(
            bytecode.to_vec(),
            tx_data.clone(),
            1000 // max_steps
        ).expect("Matrix creation failed");
        
        let elapsed = start.elapsed();
        total_time += elapsed;
        
        let metrics = matrix.get_performance_metrics();
        metrics_vec.push(metrics);
        
        if i == 0 {
            println!("  ⏱️  First execution: {:?}", elapsed);
        }
    }
    
    let avg_time = total_time / iterations as u32;
    let avg_metrics = calculate_average_metrics(&metrics_vec);
    
    println!("  📊 Average time: {:?}", avg_time);
    println!("  🎯 Avg execution steps: {}", avg_metrics.total_steps);
    println!("  ⛽ Avg gas used: {}", avg_metrics.gas_used);
    println!("  📚 Avg stack depth: {}", avg_metrics.max_stack_depth);
    println!("  💾 Avg storage slots: {}", avg_metrics.storage_slots_accessed);
    
    // Calculate throughput
    let ops_per_second = 1.0 / avg_time.as_secs_f64();
    println!("  🔥 Throughput: {:.2} executions/second", ops_per_second);
}

fn benchmark_opcode_types() {
    let opcodes = vec![
        ("ARITHMETIC", vec![0x60, 0x10, 0x60, 0x20, 0x01]), // PUSH1 16, PUSH1 32, ADD
        ("STORAGE", vec![0x60, 0x42, 0x60, 0x00, 0x55, 0x60, 0x00, 0x54]), // PUSH1 66, PUSH1 0, SSTORE, PUSH1 0, SLOAD
        ("MEMORY", vec![0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0x51]), // MSTORE, MLOAD
        ("JUMPS", vec![0x60, 0x05, 0x56, 0x00, 0x5b, 0x60, 0x01]), // PUSH1 5, JUMP, STOP, JUMPDEST, PUSH1 1
    ];
    
    for (opcode_type, bytecode) in opcodes {
        let start = Instant::now();
        
        let tx_data = TransactionData {
            from: Address::zero(),
            to: Some(Address::zero()),
            value: U256::from(1000u64),
            gas_limit: 100000,
            gas_price: U256::from(20_000_000_000u64),
            data: bytecode.clone(),
            nonce: 0,
            chain_id: Some(1),
        };
        
        let matrix = CompleteEVMExecutionMatrix::<TestField>::new(
            bytecode,
            tx_data,
            100 // max_steps
        ).expect("Matrix creation failed");
        
        let elapsed = start.elapsed();
        let metrics = matrix.get_performance_metrics();
        
        println!("  {} ops: {:?} ({} steps, {} gas)", 
            opcode_type, elapsed, metrics.total_steps, metrics.gas_used);
    }
}

fn benchmark_matrix_operations() {
    let start = Instant::now();
    
    let tx_data = TransactionData {
        from: Address::zero(),
        to: Some(Address::zero()),
        value: U256::from(1000u64),
        gas_limit: 100000,
        gas_price: U256::from(20_000_000_000u64),
        data: vec![0x60, 0x42, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3], // Simple contract
        nonce: 0,
        chain_id: Some(1),
    };
    
    let matrix = CompleteEVMExecutionMatrix::<TestField>::new(
        tx_data.data.clone(),
        tx_data,
        100 // max_steps
    ).expect("Matrix creation failed");
    
    // Test matrix creation time
    let creation_time = start.elapsed();
    println!("  🏗️  Matrix creation: {:?}", creation_time);
    
    // Test performance metrics extraction
    let metrics_start = Instant::now();
    let _metrics = matrix.get_performance_metrics();
    let metrics_time = metrics_start.elapsed();
    println!("  📊 Metrics extraction: {:?}", metrics_time);
}

fn generate_bytecode(size: usize) -> Vec<u8> {
    let mut bytecode = Vec::new();
    
    // Add some realistic opcodes
    for i in 0..size {
        match i % 10 {
            0 => bytecode.push(0x60), // PUSH1
            1 => bytecode.push((i % 256) as u8), // Random byte
            2 => bytecode.push(0x80), // DUP1
            3 => bytecode.push(0x01), // ADD
            4 => bytecode.push(0x60), // PUSH1
            5 => bytecode.push(0x00), // 0
            6 => bytecode.push(0x52), // MSTORE
            7 => bytecode.push(0x60), // PUSH1
            8 => bytecode.push(0x20), // 32
            9 => bytecode.push(0x60), // PUSH1
            _ => bytecode.push(0x00), // STOP
        }
    }
    
    // Ensure it stops cleanly
    bytecode.push(0x00); // STOP
    bytecode
}

fn calculate_average_metrics(metrics_vec: &[crate::complete_evm_matrix::ExecutionMetrics]) -> crate::complete_evm_matrix::ExecutionMetrics {
    let count = metrics_vec.len();
    if count == 0 {
        return crate::complete_evm_matrix::ExecutionMetrics {
            total_steps: 0,
            gas_used: 0,
            success: false,
            storage_slots_accessed: 0,
            max_stack_depth: 0,
        };
    }
    
    let total_steps: usize = metrics_vec.iter().map(|m| m.total_steps).sum();
    let gas_used: u64 = metrics_vec.iter().map(|m| m.gas_used).sum();
    let storage_slots: usize = metrics_vec.iter().map(|m| m.storage_slots_accessed).sum();
    let stack_depth: usize = metrics_vec.iter().map(|m| m.max_stack_depth).sum();
    let success_count = metrics_vec.iter().filter(|m| m.success).count();
    
    crate::complete_evm_matrix::ExecutionMetrics {
        total_steps: total_steps / count,
        gas_used: gas_used / count as u64,
        success: success_count > count / 2,
        storage_slots_accessed: storage_slots / count,
        max_stack_depth: stack_depth / count,
    }
}
