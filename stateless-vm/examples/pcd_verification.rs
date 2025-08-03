use avalanche_stateless_vm::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use ethereum_types::{U256, H256, Address as EthAddress};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Stateless VM with PCD Verification Example ===");
    
    // Create components for the VM
    let state_provider = Arc::new(SimpleStateProvider);
    let state_bundler = Arc::new(RwLock::new(StateBundler::new(state_provider)));
    
    // Create the PCD-based security verifier
    // This will use the deployment gateway from the EVM-Verify project
    let security_verifier = PCDVerifierFactory::create(
        None, // Use default path
        true, // Generate proofs
    )?;
    
    // Initial state
    let initial_state_root = H256::from_slice(&[0xFF; 32]);
    let initial_block_height = 12345;
    
    // Create the VM
    let mut vm = StatelessVM::new(
        state_bundler.clone(),
        security_verifier,
        initial_state_root,
        initial_block_height,
    );
    
    // Set the verification level
    vm.set_default_verification_level(VerificationLevel::Standard);
    
    println!("VM created with initial state root: {:?}", vm.state_root());
    
    // Create a transaction sequence that we want to verify
    let transactions = create_sample_transactions();
    let sequence = TransactionSequence::new(transactions, true); // Atomic execution
    
    // Just verify the sequence without executing it
    println!("Verifying transaction sequence...");
    let verification_result = vm.verify_sequence(&sequence).await?;
    
    if verification_result.is_valid() {
        println!("Sequence verification passed!");
        
        // If verification passed, execute the sequence
        println!("Executing transaction sequence...");
        let results = vm.execute_sequence(sequence).await?;
        
        // Print results
        println!("Transaction results:");
        for (i, result) in results.iter().enumerate() {
            println!("Transaction {}: {}", i, if result.is_success() { "Success" } else { "Failed" });
        }
        
        println!("New state root: {:?}", vm.state_root());
    } else {
        println!("Sequence verification failed: {}", 
                 verification_result.failure_reason().unwrap_or("Unknown reason"));
        
        if let Some(report) = verification_result.detailed_report() {
            println!("Detailed report: {}", report);
        }
        
        // Print warnings
        for warning in verification_result.warnings() {
            println!("Warning: {} ({})", warning.kind, warning.severity);
            println!("Description: {}", warning.description);
            println!("Remediation: {}", warning.remediation_hint);
            println!();
        }
    }
    
    println!("=== Example completed successfully ===");
    
    Ok(())
}

// Helper function to create sample transactions
fn create_sample_transactions() -> Vec<Transaction> {
    let sender = Address::from_slice(&[0xAA; 20]);
    let mut transactions = Vec::new();
    
    // Transaction 1: Deploy a contract
    let contract_bytecode = hex::decode("608060405234801561001057600080fd5b5060f78061001f6000396000f3fe6080604052348015600f57600080fd5b5060043610603c5760003560e01c80633fb5c1cb1460415780638381f58a146053578063d09de08a14606d575b600080fd5b6051604c3660046083565b600055565b005b605b60005481565b60405190815260200160405180910390f35b6051600080549080607c83609b565b9190505550565b600060208284031215609457600080fd5b5035919050565b60006001820160ba57634e487b7160e01b600052601160045260246000fd5b506001019056fea2646970667358221220d3fc5e36c6ef4a7c19a51d4e24b366946a3c9a72ae2c36b676f92ee207b224d364736f6c63430008130033").unwrap();
    
    let tx1 = Transaction::new(
        sender,
        None, // No target for contract creation
        U256::zero(),
        Vec::new(), // No data for contract creation
        100000.into(), // Gas limit
        20000000000.into(), // Gas price
        0, // Nonce
    )
    .with_code(contract_bytecode) // Contract bytecode
    .with_block_height(12345);
    
    transactions.push(tx1);
    
    // Transaction 2: Call a function on the deployed contract
    // This is a call to the "increment()" function
    let contract_address = Address::from_slice(&[0xBB; 20]); // Address of the deployed contract
    let function_call = hex::decode("d09de08a").unwrap(); // increment() function selector
    
    let tx2 = Transaction::new(
        sender,
        Some(contract_address),
        U256::zero(),
        function_call,
        50000.into(), // Gas limit
        20000000000.into(), // Gas price
        1, // Nonce
    )
    .with_block_height(12345);
    
    transactions.push(tx2);
    
    // Transaction 3: Call a function with parameters
    // This is a call to the "set(uint256)" function with value 42
    let function_call_with_params = hex::decode("3fb5c1cb000000000000000000000000000000000000000000000000000000000000002a").unwrap(); // set(42)
    
    let tx3 = Transaction::new(
        sender,
        Some(contract_address),
        U256::zero(),
        function_call_with_params,
        50000.into(), // Gas limit
        20000000000.into(), // Gas price
        2, // Nonce
    )
    .with_block_height(12345);
    
    transactions.push(tx3);
    
    transactions
}

// A simple state provider for this example
struct SimpleStateProvider;

#[async_trait::async_trait]
impl StateProvider for SimpleStateProvider {
    async fn fetch_state(&self, requirement: &StateRequirement) -> Result<Vec<u8>, VMError> {
        // For this example, we'll return dummy state data
        println!("Fetching state for address: {:?}, key: {:?}", requirement.address, requirement.key);
        Ok(vec![0; 32])
    }
}
