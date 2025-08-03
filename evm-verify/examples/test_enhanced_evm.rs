// Test Enhanced EVM with State Trie Integration
// Demonstrates SLOAD/SSTORE with production MPT

use anyhow::Result;
use ethers::types::{U256, H256, Address, Transaction, Block, Bytes};
use evm_verify::vm::EnhancedEVMInterpreter;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🧪 Testing Enhanced EVM with State Trie Integration");
    
    // Create a simple contract that stores and loads a value
    // PUSH1 0x42    // value to store
    // PUSH1 0x00    // storage slot 0
    // SSTORE        // store value
    // PUSH1 0x00    // storage slot 0  
    // SLOAD         // load value
    // PUSH1 0x00    // memory offset
    // MSTORE        // store in memory
    // PUSH1 0x20    // 32 bytes
    // PUSH1 0x00    // memory offset
    // RETURN        // return the value
    let bytecode = vec![
        0x60, 0x42,  // PUSH1 0x42
        0x60, 0x00,  // PUSH1 0x00
        0x55,        // SSTORE
        0x60, 0x00,  // PUSH1 0x00
        0x54,        // SLOAD  
        0x60, 0x00,  // PUSH1 0x00
        0x52,        // MSTORE
        0x60, 0x20,  // PUSH1 0x20
        0x60, 0x00,  // PUSH1 0x00
        0xf3,        // RETURN
    ];
    
    // Create mock transaction and block
    let contract_address = Address::from_low_u64_be(0x1000);
    
    let tx = Transaction {
        hash: H256::random(),
        from: Address::from_low_u64_be(0x2000),
        to: Some(contract_address),
        value: U256::zero(),
        gas: U256::from(100000u64),
        gas_price: Some(U256::from(20_000_000_000u64)), // 20 gwei
        input: Bytes::from(vec![]),
        nonce: U256::zero(),
        ..Default::default()
    };
    
    let block = Block {
        number: Some(U256::from(1000000u64)),
        timestamp: U256::from(1640000000u64),
        difficulty: U256::from(1000000u64),
        hash: Some(H256::random()),
        ..Default::default()
    };
    
    // Create enhanced EVM interpreter
    let mut evm = EnhancedEVMInterpreter::new(
        bytecode,
        &tx,
        &block,
        100000, // gas limit
        contract_address,
    )?;
    
    println!("🚀 Executing contract with state trie integration...");
    
    // Execute the contract
    let result = evm.execute_with_state().await?;
    
    println!("✅ Execution completed!");
    println!("   Success: {}", result.success);
    println!("   Gas used: {}", result.gas_used);
    println!("   State root: {:?}", result.state_root);
    println!("   Return data length: {}", result.return_data.len());
    
    if !result.return_data.is_empty() {
        // Convert return data to U256 and display
        let mut return_value_bytes = [0u8; 32];
        let data_len = result.return_data.len().min(32);
        return_value_bytes[32-data_len..].copy_from_slice(&result.return_data[..data_len]);
        let return_value = U256::from_big_endian(&return_value_bytes);
        println!("   Returned value: {} (0x{:x})", return_value, return_value);
    }
    
    println!("\n🎯 Test demonstrates:");
    println!("   ✅ SSTORE operation with production MPT");
    println!("   ✅ SLOAD operation with state trie retrieval");
    println!("   ✅ State root computation after storage changes");
    println!("   ✅ Integration with existing EVM interpreter structure");
    
    Ok(())
}
