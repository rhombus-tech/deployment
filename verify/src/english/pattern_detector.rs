// Pattern Detector - Identifies standard contract patterns
use super::*;

#[derive(Debug, Clone, PartialEq)]
pub enum ContractPattern {
    Token,           // ERC20-like fungible token
    NFT,             // ERC721-like non-fungible token
    Escrow,          // Payment escrow with arbitration
    Staking,         // Token staking with rewards
    DAO,             // Governance/voting
    MultiSig,        // Multi-signature wallet
    Vesting,         // Token vesting schedule
    Custom,          // Doesn't match a pattern, use AI
}

pub struct PatternDetector;

impl PatternDetector {
    pub fn detect(contract: &EnglishContract) -> ContractPattern {
        // Check for token patterns
        if Self::is_token_pattern(contract) {
            return ContractPattern::Token;
        }
        
        // Check for NFT patterns
        if Self::is_nft_pattern(contract) {
            return ContractPattern::NFT;
        }
        
        // Check for escrow patterns
        if Self::is_escrow_pattern(contract) {
            return ContractPattern::Escrow;
        }
        
        // Check for staking patterns
        if Self::is_staking_pattern(contract) {
            return ContractPattern::Staking;
        }
        
        // Check for DAO patterns
        if Self::is_dao_pattern(contract) {
            return ContractPattern::DAO;
        }
        
        // Check for multisig patterns
        if Self::is_multisig_pattern(contract) {
            return ContractPattern::MultiSig;
        }
        
        // Check for vesting patterns
        if Self::is_vesting_pattern(contract) {
            return ContractPattern::Vesting;
        }
        
        // Default to custom (use AI)
        ContractPattern::Custom
    }
    
    fn is_token_pattern(contract: &EnglishContract) -> bool {
        let function_names: Vec<String> = contract.functions
            .iter()
            .map(|f| f.name.to_lowercase())
            .collect();
        
        // Token contracts typically have transfer, balance_of, and often mint/burn
        let has_transfer = function_names.iter().any(|n| n.contains("transfer"));
        let has_balance = function_names.iter().any(|n| n.contains("balance"));
        
        // Check state variables for token-like properties
        let has_balances = contract.state.iter().any(|s| 
            s.name.to_lowercase().contains("balance") || 
            s.name.to_lowercase().contains("supply")
        );
        
        has_transfer && has_balance && has_balances
    }
    
    fn is_nft_pattern(contract: &EnglishContract) -> bool {
        let function_names: Vec<String> = contract.functions
            .iter()
            .map(|f| f.name.to_lowercase())
            .collect();
        
        // NFT contracts have owner_of, token_uri, mint
        let has_owner_of = function_names.iter().any(|n| n.contains("owner"));
        let has_token_uri = function_names.iter().any(|n| n.contains("uri") || n.contains("metadata"));
        let has_mint = function_names.iter().any(|n| n.contains("mint"));
        
        has_owner_of || (has_token_uri && has_mint)
    }
    
    fn is_escrow_pattern(contract: &EnglishContract) -> bool {
        let function_names: Vec<String> = contract.functions
            .iter()
            .map(|f| f.name.to_lowercase())
            .collect();
        
        // Escrow has create, release/complete, dispute/refund
        let has_create = function_names.iter().any(|n| n.contains("create") || n.contains("deposit"));
        let has_release = function_names.iter().any(|n| n.contains("release") || n.contains("complete"));
        let has_dispute = function_names.iter().any(|n| n.contains("dispute") || n.contains("refund"));
        
        has_create && (has_release || has_dispute)
    }
    
    fn is_staking_pattern(contract: &EnglishContract) -> bool {
        let function_names: Vec<String> = contract.functions
            .iter()
            .map(|f| f.name.to_lowercase())
            .collect();
        
        // Staking has stake, unstake, claim rewards
        let has_stake = function_names.iter().any(|n| n.contains("stake"));
        let has_unstake = function_names.iter().any(|n| n.contains("unstake") || n.contains("withdraw"));
        let has_rewards = function_names.iter().any(|n| n.contains("reward") || n.contains("claim"));
        
        has_stake && (has_unstake || has_rewards)
    }
    
    fn is_dao_pattern(contract: &EnglishContract) -> bool {
        let function_names: Vec<String> = contract.functions
            .iter()
            .map(|f| f.name.to_lowercase())
            .collect();
        
        // DAO has propose, vote, execute
        let has_propose = function_names.iter().any(|n| n.contains("propose") || n.contains("proposal"));
        let has_vote = function_names.iter().any(|n| n.contains("vote"));
        let has_execute = function_names.iter().any(|n| n.contains("execute"));
        
        has_propose && has_vote && has_execute
    }
    
    fn is_multisig_pattern(contract: &EnglishContract) -> bool {
        let function_names: Vec<String> = contract.functions
            .iter()
            .map(|f| f.name.to_lowercase())
            .collect();
        
        // Multisig has submit, approve/sign, execute
        let has_submit = function_names.iter().any(|n| n.contains("submit") || n.contains("propose"));
        let has_approve = function_names.iter().any(|n| n.contains("approve") || n.contains("sign") || n.contains("confirm"));
        let has_execute = function_names.iter().any(|n| n.contains("execute"));
        
        has_submit && has_approve && has_execute
    }
    
    fn is_vesting_pattern(contract: &EnglishContract) -> bool {
        let function_names: Vec<String> = contract.functions
            .iter()
            .map(|f| f.name.to_lowercase())
            .collect();
        
        // Vesting has create schedule, release/claim
        let has_schedule = function_names.iter().any(|n| 
            n.contains("vest") || n.contains("schedule") || n.contains("lock")
        );
        let has_release = function_names.iter().any(|n| n.contains("release") || n.contains("claim"));
        
        has_schedule && has_release
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    
    #[test]
    fn test_detect_token() {
        let contract = EnglishContract {
            name: "MyToken".to_string(),
            description: "A token".to_string(),
            config: HashMap::new(),
            state: vec![
                StateVariable {
                    name: "balances".to_string(),
                    var_type: "HashMap".to_string(),
                    description: "".to_string(),
                    initial_value: None,
                },
            ],
            functions: vec![
                ContractFunction {
                    name: "transfer".to_string(),
                    description: "".to_string(),
                    parameters: vec![],
                    returns: vec![],
                    requirements: vec![],
                    steps: vec![],
                    visibility: Visibility::Public,
                },
                ContractFunction {
                    name: "balance_of".to_string(),
                    description: "".to_string(),
                    parameters: vec![],
                    returns: vec![],
                    requirements: vec![],
                    steps: vec![],
                    visibility: Visibility::Public,
                },
            ],
            events: vec![],
        };
        
        assert_eq!(PatternDetector::detect(&contract), ContractPattern::Token);
    }
    
    #[test]
    fn test_detect_dao() {
        let contract = EnglishContract {
            name: "MyDAO".to_string(),
            description: "A DAO".to_string(),
            config: HashMap::new(),
            state: vec![],
            functions: vec![
                ContractFunction {
                    name: "create_proposal".to_string(),
                    description: "".to_string(),
                    parameters: vec![],
                    returns: vec![],
                    requirements: vec![],
                    steps: vec![],
                    visibility: Visibility::Public,
                },
                ContractFunction {
                    name: "vote".to_string(),
                    description: "".to_string(),
                    parameters: vec![],
                    returns: vec![],
                    requirements: vec![],
                    steps: vec![],
                    visibility: Visibility::Public,
                },
                ContractFunction {
                    name: "execute".to_string(),
                    description: "".to_string(),
                    parameters: vec![],
                    returns: vec![],
                    requirements: vec![],
                    steps: vec![],
                    visibility: Visibility::Public,
                },
            ],
            events: vec![],
        };
        
        assert_eq!(PatternDetector::detect(&contract), ContractPattern::DAO);
    }
}
