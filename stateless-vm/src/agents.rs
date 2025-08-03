use crate::errors::{VMError, Result};
use crate::transaction::{Transaction, TransactionSequence};
use crate::state::{StateRequirement, StateAccessPattern};
use crate::types::{Address, Bytes, BlockHeight, Gas};
use async_trait::async_trait;
use ethereum_types::U256;
use serde::{Serialize, Deserialize};

/// Represents an action performed by an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAction {
    /// Type of action
    pub action_type: ActionType,
    /// Target of the action (e.g., contract address)
    pub target: Option<Address>,
    /// Input data for the action
    pub input: Bytes,
    /// Value to send with the action
    pub value: U256,
    /// Estimated gas for the action
    pub estimated_gas: Gas,
    /// Maximum allowed slippage (for DEX operations)
    pub max_slippage: Option<u8>,
    /// Reference to related actions (for multi-step operations)
    pub related_actions: Vec<usize>,
    /// Custom metadata
    pub metadata: serde_json::Value,
}

/// Type of agent action
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    /// Simple transfer of native tokens
    Transfer,
    /// Swap tokens on a DEX
    Swap,
    /// Provide liquidity to a pool
    ProvideLiquidity,
    /// Remove liquidity from a pool
    RemoveLiquidity,
    /// Deposit into a lending protocol
    Deposit,
    /// Borrow from a lending protocol
    Borrow,
    /// Repay a loan
    Repay,
    /// Stake tokens
    Stake,
    /// Unstake tokens
    Unstake,
    /// Claim rewards
    ClaimRewards,
    /// Vote in governance
    Vote,
    /// Deploy a contract
    Deploy,
    /// Generic call to a contract
    Call,
    /// Compound multiple actions
    Compound,
    /// Flash loan
    FlashLoan,
    /// Custom action type
    Custom(String),
}

/// Context for agent execution
#[derive(Debug, Clone)]
pub struct AgentContext {
    /// Block height for this execution
    pub block_height: BlockHeight,
    /// Gas price
    pub gas_price: Gas,
    /// Available balance
    pub balance: U256,
    /// Maximum allowed slippage
    pub max_slippage: u8,
    /// Default gas limit
    pub default_gas_limit: Gas,
}

/// Interface for agent interactions
#[async_trait]
pub trait AgentInterface: Send + Sync {
    /// Plan a sequence of actions
    async fn plan_actions(&self, context: &AgentContext) -> Result<Vec<AgentAction>>;
    
    /// Convert actions to transactions
    async fn actions_to_transactions(&self, actions: &[AgentAction], context: &AgentContext) -> Result<TransactionSequence>;
    
    /// Handle action failure
    async fn handle_failure(&self, action: &AgentAction, error: &VMError) -> Result<Option<AgentAction>>;
    
    /// Get state requirements for an action
    async fn get_state_requirements(&self, action: &AgentAction) -> Result<Vec<StateRequirement>>;
}

/// Handles agent actions and converts them to VM transactions
pub struct AgentHandler {
    /// Agent implementation
    agent: Box<dyn AgentInterface>,
    /// Agent context
    context: AgentContext,
    /// Agent address
    address: Address,
}

impl AgentHandler {
    /// Create a new agent handler
    pub fn new(
        agent: Box<dyn AgentInterface>,
        context: AgentContext,
        address: Address,
    ) -> Self {
        Self {
            agent,
            context,
            address,
        }
    }
    
    /// Plan and execute a sequence of actions
    pub async fn plan_and_execute(&self) -> Result<TransactionSequence> {
        // Plan actions
        let actions = self.agent.plan_actions(&self.context).await?;
        
        // Convert to transactions
        let mut sequence = self.agent.actions_to_transactions(&actions, &self.context).await?;
        
        // Analyze state requirements for the entire sequence
        let mut state_requirements = Vec::new();
        
        for action in &actions {
            let action_requirements = self.agent.get_state_requirements(action).await?;
            state_requirements.extend(action_requirements);
        }
        
        // Add the state requirements to the sequence
        for requirement in state_requirements {
            sequence.add_state(requirement.clone(), Vec::new()); // Placeholder for state data
        }
        
        Ok(sequence)
    }
    
    /// Handle action failure and retry
    pub async fn handle_failure(&self, action: &AgentAction, error: &VMError) -> Result<Option<AgentAction>> {
        self.agent.handle_failure(action, error).await
    }
}

/// Default implementation with common functionality
pub struct DefaultAgentInterface {
    /// From address for transactions
    from: Address,
    /// Fallback handler for unknown actions
    fallback_handler: Option<Box<dyn AgentInterface>>,
}

impl DefaultAgentInterface {
    /// Create a new default agent interface
    pub fn new(from: Address) -> Self {
        Self {
            from,
            fallback_handler: None,
        }
    }
    
    /// Set a fallback handler
    pub fn with_fallback(mut self, handler: Box<dyn AgentInterface>) -> Self {
        self.fallback_handler = Some(handler);
        self
    }
    
    /// Convert a single action to a transaction
    pub async fn action_to_transaction(&self, action: &AgentAction, context: &AgentContext, nonce: u64) -> Result<Transaction> {
        let gas_limit = action.estimated_gas;
        
        match action.action_type {
            ActionType::Transfer => {
                if let Some(target) = action.target {
                    let tx = Transaction::new(
                        self.from,
                        Some(target),
                        action.value,
                        Vec::new(), // No data for simple transfers
                        gas_limit,
                        context.gas_price,
                        nonce,
                    ).with_block_height(context.block_height);
                    
                    Ok(tx)
                } else {
                    Err(VMError::InvalidTransaction {
                        reason: "Transfer action missing target address".into(),
                    })
                }
            },
            ActionType::Call => {
                if let Some(target) = action.target {
                    let tx = Transaction::new(
                        self.from,
                        Some(target),
                        action.value,
                        action.input.clone(),
                        gas_limit,
                        context.gas_price,
                        nonce,
                    ).with_block_height(context.block_height);
                    
                    Ok(tx)
                } else {
                    Err(VMError::InvalidTransaction {
                        reason: "Call action missing target address".into(),
                    })
                }
            },
            ActionType::Deploy => {
                let tx = Transaction::new(
                    self.from,
                    None, // No target for contract creation
                    action.value,
                    Vec::new(), // Constructor args will be in code
                    gas_limit,
                    context.gas_price,
                    nonce,
                )
                .with_code(action.input.clone())
                .with_block_height(context.block_height);
                
                Ok(tx)
            },
            _ => {
                // For other action types, delegate to the appropriate specialized handler
                // For now, we'll treat them as generic calls
                if let Some(target) = action.target {
                    let tx = Transaction::new(
                        self.from,
                        Some(target),
                        action.value,
                        action.input.clone(),
                        gas_limit,
                        context.gas_price,
                        nonce,
                    ).with_block_height(context.block_height);
                    
                    Ok(tx)
                } else if let Some(fallback) = &self.fallback_handler {
                    // Use fallback handler's implementation if available
                    let actions = vec![action.clone()];
                    let sequence = fallback.actions_to_transactions(&actions, context).await?;
                    
                    if let Some(tx) = sequence.transactions().first() {
                        Ok(tx.clone())
                    } else {
                        Err(VMError::InvalidTransaction {
                            reason: "Fallback handler did not produce any transactions".into(),
                        })
                    }
                } else {
                    Err(VMError::InvalidTransaction {
                        reason: format!("Unsupported action type: {:?}", action.action_type),
                    })
                }
            }
        }
    }
}

#[async_trait]
impl AgentInterface for DefaultAgentInterface {
    async fn plan_actions(&self, _context: &AgentContext) -> Result<Vec<AgentAction>> {
        // The default implementation doesn't plan actions
        // It's meant to be used for converting actions to transactions
        if let Some(fallback) = &self.fallback_handler {
            fallback.plan_actions(_context).await
        } else {
            Err(VMError::InvalidOperation {
                description: "Default agent interface cannot plan actions".into(),
            })
        }
    }
    
    async fn actions_to_transactions(&self, actions: &[AgentAction], context: &AgentContext) -> Result<TransactionSequence> {
        let mut transactions = Vec::new();
        
        // Convert each action to a transaction
        for (i, action) in actions.iter().enumerate() {
            let tx = self.action_to_transaction(action, context, i as u64).await?;
            transactions.push(tx);
        }
        
        // Get the priority from the first transaction if available
        let priority = transactions.first().map(|tx| tx.priority);
        
        // Create a transaction sequence
        let mut sequence = TransactionSequence::new(transactions, true); // Atomic by default
        
        // Add the priority if we have one
        if let Some(p) = priority {
            sequence = sequence.with_priority(p);
        }
        
        Ok(sequence)
    }
    
    async fn handle_failure(&self, action: &AgentAction, error: &VMError) -> Result<Option<AgentAction>> {
        // The default implementation simply returns None (no retry)
        if let Some(fallback) = &self.fallback_handler {
            fallback.handle_failure(action, error).await
        } else {
            Ok(None)
        }
    }
    
    async fn get_state_requirements(&self, action: &AgentAction) -> Result<Vec<StateRequirement>> {
        let mut requirements = Vec::new();
        
        // Default implementation adds basic state requirements
        if let Some(target) = action.target {
            // For most actions, we need the target contract's code
            let code_requirement = StateRequirement {
                address: target,
                key: ethereum_types::H256::from_low_u64_be(0), // Special key for code
                block_height: 0, // Will be filled in later
                access_pattern: StateAccessPattern::ReadOnly,
            };
            
            requirements.push(code_requirement);
            
            // For most actions, we need the target contract's balance
            let balance_requirement = StateRequirement {
                address: target,
                key: ethereum_types::H256::from_low_u64_be(1), // Special key for balance
                block_height: 0, // Will be filled in later
                access_pattern: StateAccessPattern::ReadOnly,
            };
            
            requirements.push(balance_requirement);
        }
        
        // Use fallback if available
        if let Some(fallback) = &self.fallback_handler {
            let fallback_requirements = fallback.get_state_requirements(action).await?;
            requirements.extend(fallback_requirements);
        }
        
        Ok(requirements)
    }
}
