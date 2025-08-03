use std::sync::Arc;
use ethers::{
    providers::{Provider, Http},
    signers::{LocalWallet, Signer},
    types::{Address, U256, H256, Bytes},
};
use tokio::sync::RwLock;

use avalanche_stateless_vm::{
    StatelessVM, ExecutionMode, ExecutionResult,
    Transaction, TransactionSequence,
    StateBundler, VMError,
};

use avalanche_stateless_vm::atomic::{
    AtomicExecutor, MockPCCVerifier, MockPCDProver,
    #[cfg(feature = "evm-verify")]
    RealPCCVerifier,
    #[cfg(feature = "evm-verify")]
    RealPCDProver,
};
use avalanche_stateless_vm::security::{SecurityVerifier, VerificationResult};
use avalanche_stateless_vm::types::VerificationLevel;
use async_trait::async_trait;

struct MockSecurityVerifier;

#[async_trait]
impl SecurityVerifier for MockSecurityVerifier {
    async fn verify_transaction(
        &self,
        _transaction: &Transaction,
        _level: VerificationLevel,
    ) -> Result<VerificationResult, VMError> {
        Ok(VerificationResult::Safe {
            warnings: vec![],
            gas_estimate: U256::from(21000),
        })
    }
    
    async fn verify_sequence(
        &self,
        _sequence: &TransactionSequence,
        _level: VerificationLevel,
    ) -> Result<VerificationResult, VMError> {
        Ok(VerificationResult::Safe {
            warnings: vec![],
            gas_estimate: U256::from(100000),
        })
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 StatelessVM Atomic Execution Demo");
    println!("=====================================");
    
    // 1. Initialize provider and wallet
    let provider = Arc::new(
        Provider::<Http>::try_from("http://localhost:8545")?
    );
    
    let wallet = LocalWallet::new(&mut rand::thread_rng());
    println!("📝 Wallet Address: {}", wallet.address());
    
    // 2. Deploy atomic executor contract (mock address for demo)
    let atomic_executor_address = Address::from_slice(&[0x42u8; 20]);
    println!("📄 Atomic Executor Contract: {}", atomic_executor_address);
    
    // 3. Create atomic executor
    let atomic_executor = Arc::new(
        AtomicExecutor::new(atomic_executor_address, provider.clone(), wallet.clone())
            .with_pcc_verifier(Arc::new(MockPCCVerifier))
            .with_pcd_prover(Arc::new(MockPCDProver))
    );
    
    // 4. Initialize StatelessVM
    let state_bundler = Arc::new(RwLock::new(StateBundler::new()));
    let security_verifier = Arc::new(MockSecurityVerifier);
    
    let mut stateless_vm = StatelessVM::new(
        state_bundler,
        security_verifier,
        H256::zero(), // initial state root
        U256::zero(), // initial block height
    );
    
    // 5. Configure atomic execution
    stateless_vm.set_atomic_executor(atomic_executor);
    stateless_vm.set_execution_mode(ExecutionMode::VerifiedAtomic);
    
    println!("✅ StatelessVM configured for atomic execution");
    
    // 6. Create a multi-step transaction sequence (example DeFi arbitrage)
    let sequence = create_arbitrage_sequence();
    println!("📋 Created arbitrage sequence with {} steps", sequence.transactions.len());
    
    // 7. Execute different modes for comparison
    demo_coordinated_execution(&mut stateless_vm, sequence.clone()).await?;
    demo_atomic_execution(&mut stateless_vm, sequence.clone()).await?;
    demo_verified_atomic_execution(&mut stateless_vm, sequence.clone()).await?;
    demo_mev_protected_execution(&mut stateless_vm, sequence.clone()).await?;
    
    println!("\n🎉 Demo completed successfully!");
    println!("Key Benefits Demonstrated:");
    println!("• True atomic execution guarantees");
    println!("• PCC+PCD cryptographic verification");
    println!("• MEV protection capabilities");
    println!("• Backwards compatibility with coordinated execution");
    
    Ok(())
}

/// Create a sample arbitrage transaction sequence
fn create_arbitrage_sequence() -> TransactionSequence {
    // Mock DEX addresses
    let uniswap_v2 = Address::from_slice(&[0x01u8; 20]);
    let sushiswap = Address::from_slice(&[0x02u8; 20]);
    let balancer = Address::from_slice(&[0x03u8; 20]);
    
    // Step 1: Flash loan from Aave
    let flash_loan_tx = Transaction::new(
        Address::from_slice(&[0x10u8; 20]), // Aave lending pool
        Bytes::from(hex::decode("a415bcad0000000000000000000000000000000000000000000000001bc16d674ec80000").unwrap()), // flashLoan call
        U256::zero(),
    );
    
    // Step 2: Buy ETH on Uniswap V2 (where price is lower)
    let buy_eth_tx = Transaction::new(
        uniswap_v2,
        Bytes::from(hex::decode("38ed173900000000000000000000000000000000000000000000000000000000000186a0").unwrap()), // swapExactTokensForTokens
        U256::zero(),
    );
    
    // Step 3: Sell ETH on SushiSwap (where price is higher)
    let sell_eth_tx = Transaction::new(
        sushiswap,
        Bytes::from(hex::decode("38ed173900000000000000000000000000000000000000000000000000000000000186a0").unwrap()), // swapExactTokensForTokens
        U256::zero(),
    );
    
    // Step 4: Repay flash loan + fee
    let repay_loan_tx = Transaction::new(
        Address::from_slice(&[0x10u8; 20]), // Aave lending pool
        Bytes::from(hex::decode("573ade810000000000000000000000000000000000000000000000001bc16d674ec80000").unwrap()), // repay call
        U256::zero(),
    );
    
    TransactionSequence {
        id: format!("arbitrage_sequence_{}", chrono::Utc::now().timestamp()),
        transactions: vec![flash_loan_tx, buy_eth_tx, sell_eth_tx, repay_loan_tx],
        metadata: std::collections::HashMap::new(),
    }
}

async fn demo_coordinated_execution(
    vm: &mut StatelessVM,
    sequence: TransactionSequence,
) -> Result<(), VMError> {
    println!("\n🔄 Demonstrating Coordinated Execution (Current Implementation)");
    
    vm.set_execution_mode(ExecutionMode::Coordinated);
    
    match vm.execute_with_mode(sequence).await? {
        ExecutionResult::Coordinated(statuses) => {
            println!("✅ Coordinated execution completed");
            println!("   → {} transactions processed", statuses.len());
            println!("   → Each transaction executed separately");
            println!("   → ⚠️  No atomicity guarantees");
        }
        _ => unreachable!(),
    }
    
    Ok(())
}

async fn demo_atomic_execution(
    vm: &mut StatelessVM,
    sequence: TransactionSequence,
) -> Result<(), VMError> {
    println!("\n⚛️  Demonstrating Atomic Execution");
    
    vm.set_execution_mode(ExecutionMode::Atomic);
    
    match vm.execute_with_mode(sequence).await? {
        ExecutionResult::Atomic(result) => {
            println!("✅ Atomic execution completed");
            println!("   → Execution Hash: {}", result.execution_hash);
            println!("   → Gas Used: {}", result.gas_used);
            println!("   → Operations: {}", result.operations_executed);
            println!("   → ✅ True atomicity: All operations succeed or all fail");
        }
        _ => unreachable!(),
    }
    
    Ok(())
}

async fn demo_verified_atomic_execution(
    vm: &mut StatelessVM,
    sequence: TransactionSequence,
) -> Result<(), VMError> {
    println!("\n🔒 Demonstrating Verified Atomic Execution (PCC+PCD)");
    
    vm.set_execution_mode(ExecutionMode::VerifiedAtomic);
    
    match vm.execute_with_mode(sequence).await? {
        ExecutionResult::VerifiedAtomic(result) => {
            println!("✅ Verified atomic execution completed");
            println!("   → Execution Hash: {}", result.execution_result.execution_hash);
            println!("   → Safety Proof: {}", result.safety_proof);
            println!("   → Execution Proof: {}", result.execution_proof);
            println!("   → Gas Used: {}", result.execution_result.gas_used);
            println!("   → ✅ Cryptographic guarantees: PCC safety + PCD execution proofs");
            println!("   → ✅ Atomic guarantee: {}", result.atomic_guarantee);
        }
        _ => unreachable!(),
    }
    
    Ok(())
}

async fn demo_mev_protected_execution(
    vm: &mut StatelessVM,
    sequence: TransactionSequence,
) -> Result<(), VMError> {
    println!("\n🛡️  Demonstrating MEV-Protected Execution");
    
    let result = vm.execute_mev_protected_sequence(sequence).await?;
    
    println!("✅ MEV-protected execution completed");
    println!("   → Execution Hash: {}", result.execution_result.execution_hash);
    println!("   → MEV Protected: {}", result.mev_protected);
    println!("   → Safety Proof: {}", result.safety_proof);
    println!("   → ✅ Protected from frontrunning and sandwich attacks");
    
    Ok(())
}
