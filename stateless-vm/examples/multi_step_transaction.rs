use stateless_vm::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use ethereum_types::{U256, H256, Address as EthAddress};
use serde_json::json;

// Define a simple implementation of SecurityVerifier for this example
struct SimpleSecurityVerifier;

#[async_trait::async_trait]
impl SecurityVerifier for SimpleSecurityVerifier {
    async fn verify_transaction(
        &self, 
        _transaction: &Transaction,
        _level: VerificationLevel,
    ) -> Result<VerificationResult, VMError> {
        // For this example, we'll assume all transactions are secure
        Ok(VerificationResult::success())
    }
    
    async fn verify_sequence(
        &self,
        _sequence: &TransactionSequence,
        _level: VerificationLevel,
    ) -> Result<VerificationResult, VMError> {
        // For this example, we'll assume all sequences are secure
        Ok(VerificationResult::success())
    }
}

// Define a simple implementation of StateProvider for this example
struct SimpleStateProvider;

#[async_trait::async_trait]
impl StateProvider for SimpleStateProvider {
    async fn fetch_state(&self, requirement: &StateRequirement) -> Result<Vec<u8>, VMError> {
        // For this example, we'll return dummy state data
        println!("Fetching state for address: {:?}, key: {:?}", requirement.address, requirement.key);
        Ok(vec![0; 32])
    }
}

// Define a simple implementation of AgentInterface for this example
struct SwapAgent {
    router_address: Address,
}

impl SwapAgent {
    fn new(router_address: Address) -> Self {
        Self { router_address }
    }
}

#[async_trait::async_trait]
impl AgentInterface for SwapAgent {
    async fn plan_actions(&self, context: &AgentContext) -> Result<Vec<AgentAction>, VMError> {
        println!("Planning swap actions at block height: {}", context.block_height);
        
        // For this example, we'll create a two-step swap operation
        let token_a = Address::from_slice(&[0x01; 20]);
        let token_b = Address::from_slice(&[0x02; 20]);
        
        // Step 1: Approve the router to spend our tokens
        let approve_action = AgentAction {
            action_type: ActionType::Call,
            target: Some(token_a),
            input: hex::decode("095ea7b3000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000ff").unwrap(), // approve(address,uint256)
            value: U256::zero(),
            estimated_gas: 50000.into(),
            max_slippage: None,
            related_actions: vec![1], // Related to the next action
            metadata: json!({ "description": "Approve Token A for swap" }),
        };
        
        // Step 2: Execute the swap
        let swap_action = AgentAction {
            action_type: ActionType::Swap,
            target: Some(self.router_address),
            input: hex::decode("38ed1739000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap(), // swapExactTokensForTokens(uint256,uint256,address[],address,uint256)
            value: U256::zero(),
            estimated_gas: 150000.into(),
            max_slippage: Some(5), // 5% slippage
            related_actions: vec![0], // Related to the previous action
            metadata: json!({ "description": "Swap Token A for Token B" }),
        };
        
        Ok(vec![approve_action, swap_action])
    }
    
    async fn actions_to_transactions(&self, actions: &[AgentAction], context: &AgentContext) -> Result<TransactionSequence, VMError> {
        // For this example, we'll use a simplified conversion logic
        let mut transactions = Vec::new();
        let sender = Address::from_slice(&[0xAA; 20]);
        
        for (i, action) in actions.iter().enumerate() {
            let tx = Transaction::new(
                sender,
                action.target,
                action.value,
                action.input.clone(),
                action.estimated_gas,
                context.gas_price,
                i as u64, // Use index as nonce
            ).with_block_height(context.block_height);
            
            transactions.push(tx);
        }
        
        // Create a transaction sequence that must be executed atomically
        Ok(TransactionSequence::new(transactions, true))
    }
    
    async fn handle_failure(&self, action: &AgentAction, error: &VMError) -> Result<Option<AgentAction>, VMError> {
        // For this example, we'll just log the error and not retry
        println!("Action failed: {:?}, error: {}", action.action_type, error);
        Ok(None)
    }
    
    async fn get_state_requirements(&self, action: &AgentAction) -> Result<Vec<StateRequirement>, VMError> {
        let mut requirements = Vec::new();
        
        if let Some(target) = action.target {
            // For contract interactions, we need the contract code
            requirements.push(StateRequirement {
                address: target,
                key: H256::from_low_u64_be(0), // Key for contract code
                block_height: 0, // Latest block
                access_pattern: StateAccessPattern::ReadOnly,
            });
            
            // For swaps, we also need token balances
            if action.action_type == ActionType::Swap {
                requirements.push(StateRequirement {
                    address: target,
                    key: H256::from_low_u64_be(1), // Key for balance
                    block_height: 0, // Latest block
                    access_pattern: StateAccessPattern::ReadWrite,
                });
            }
        }
        
        Ok(requirements)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Stateless VM Multi-Step Transaction Example ===");
    
    // Create components for the VM
    let state_provider = Arc::new(SimpleStateProvider);
    let state_bundler = Arc::new(RwLock::new(StateBundler::new(state_provider)));
    let security_verifier = Arc::new(SimpleSecurityVerifier);
    
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
    
    // Create an agent for multi-step transactions
    let router_address = Address::from_slice(&[0xBB; 20]);
    let swap_agent = Box::new(SwapAgent::new(router_address));
    
    // Create agent context
    let agent_context = AgentContext {
        block_height: vm.block_height(),
        gas_price: 20000000000.into(), // 20 gwei
        balance: U256::from(1000000000000000000u64), // 1 ETH
        max_slippage: 5, // 5%
        default_gas_limit: 300000.into(),
    };
    
    // Execute agent actions
    let agent_address = Address::from_slice(&[0xAA; 20]);
    println!("Executing agent actions...");
    
    let results = vm.execute_agent_actions(
        swap_agent,
        agent_context,
        agent_address,
    ).await?;
    
    // Print results
    println!("Transaction results:");
    for (i, result) in results.iter().enumerate() {
        println!("Transaction {}: {}", i, if result.is_success() { "Success" } else { "Failed" });
    }
    
    println!("New state root: {:?}", vm.state_root());
    println!("=== Example completed successfully ===");
    
    Ok(())
}
