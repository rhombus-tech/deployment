// Template Generator - Generates code from templates for known patterns
use super::*;
use super::pattern_detector::ContractPattern;

pub struct TemplateGenerator;

impl TemplateGenerator {
    pub fn generate(contract: &EnglishContract, pattern: &ContractPattern) -> String {
        match pattern {
            ContractPattern::Token => Self::generate_token(contract),
            ContractPattern::NFT => Self::generate_nft(contract),
            ContractPattern::Escrow => Self::generate_escrow(contract),
            ContractPattern::Staking => Self::generate_staking(contract),
            ContractPattern::DAO => Self::generate_dao(contract),
            ContractPattern::MultiSig => Self::generate_multisig(contract),
            ContractPattern::Vesting => Self::generate_vesting(contract),
            ContractPattern::Custom => panic!("Use AI mode for custom contracts"),
        }
    }
    
    fn generate_token(contract: &EnglishContract) -> String {
        // Extract config values
        let total_supply = contract.config.get("Total Supply")
            .or(contract.config.get("total_supply"))
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.replace(",", "").parse::<u64>().ok())
            .unwrap_or(1_000_000);
        
        format!(r#"use borsh::{{BorshDeserialize, BorshSerialize}};
use std::collections::HashMap;

#[derive(BorshSerialize, BorshDeserialize, Default, Clone)]
pub struct TokenState {{
    pub balances: HashMap<Vec<u8>, u64>,
    pub allowances: HashMap<(Vec<u8>, Vec<u8>), u64>,
    pub total_supply: u64,
    pub owner: Vec<u8>,
}}

// Helper to safely read parameters
fn read_params(ptr: *const u8, len: i32) -> Result<Vec<u8>, ()> {{
    if len < 0 || len > 1024 {{
        return Err(()); // Parameter validation
    }}
    Ok(unsafe {{ std::slice::from_raw_parts(ptr, len as usize).to_vec() }})
}}

#[no_mangle]
pub extern "C" fn initialize(deployer_ptr: *const u8, deployer_len: i32) -> Vec<u8> {{
    let deployer = match read_params(deployer_ptr, deployer_len) {{
        Ok(d) => d,
        Err(_) => return Vec::new(),
    }};
    
    let mut state = TokenState::default();
    state.owner = deployer.clone();
    state.balances.insert(deployer, {total_supply});
    state.total_supply = {total_supply};
    
    borsh::to_vec(&state).unwrap_or_default()
}}

#[no_mangle]
pub extern "C" fn transfer(
    state_ptr: *const u8,
    state_len: i32,
    sender_ptr: *const u8,
    sender_len: i32,
    recipient_ptr: *const u8,
    recipient_len: i32,
    amount: u64
) -> Vec<u8> {{
    // Read parameters
    let state_bytes = match read_params(state_ptr, state_len) {{
        Ok(s) => s,
        Err(_) => return Vec::new(),
    }};
    let sender = match read_params(sender_ptr, sender_len) {{
        Ok(s) => s,
        Err(_) => return Vec::new(),
    }};
    let recipient = match read_params(recipient_ptr, recipient_len) {{
        Ok(r) => r,
        Err(_) => return Vec::new(),
    }};
    
    // Deserialize state
    let mut state: TokenState = match TokenState::try_from_slice(&state_bytes) {{
        Ok(s) => s,
        Err(_) => return Vec::new(),
    }};
    
    // Validation
    if amount == 0 {{
        return Vec::new();
    }}
    
    let sender_balance = state.balances.get(&sender).copied().unwrap_or(0);
    if sender_balance < amount {{
        return Vec::new(); // Insufficient balance
    }}
    
    // Transfer
    state.balances.insert(sender.clone(), sender_balance - amount);
    let recipient_balance = state.balances.get(&recipient).copied().unwrap_or(0);
    state.balances.insert(recipient, recipient_balance + amount);
    
    borsh::to_vec(&state).unwrap_or_default()
}}

#[no_mangle]
pub extern "C" fn balance_of(
    state_ptr: *const u8,
    state_len: i32,
    account_ptr: *const u8,
    account_len: i32
) -> Vec<u8> {{
    let state_bytes = match read_params(state_ptr, state_len) {{
        Ok(s) => s,
        Err(_) => return Vec::new(),
    }};
    let account = match read_params(account_ptr, account_len) {{
        Ok(a) => a,
        Err(_) => return Vec::new(),
    }};
    
    let state: TokenState = match TokenState::try_from_slice(&state_bytes) {{
        Ok(s) => s,
        Err(_) => return Vec::new(),
    }};
    
    let balance = state.balances.get(&account).copied().unwrap_or(0);
    borsh::to_vec(&balance).unwrap_or_default()
}}

#[no_mangle]
pub extern "C" fn approve(
    state_ptr: *const u8,
    state_len: i32,
    owner_ptr: *const u8,
    owner_len: i32,
    spender_ptr: *const u8,
    spender_len: i32,
    amount: u64
) -> Vec<u8> {{
    let state_bytes = match read_params(state_ptr, state_len) {{
        Ok(s) => s,
        Err(_) => return Vec::new(),
    }};
    let owner = match read_params(owner_ptr, owner_len) {{
        Ok(o) => o,
        Err(_) => return Vec::new(),
    }};
    let spender = match read_params(spender_ptr, spender_len) {{
        Ok(s) => s,
        Err(_) => return Vec::new(),
    }};
    
    let mut state: TokenState = match TokenState::try_from_slice(&state_bytes) {{
        Ok(s) => s,
        Err(_) => return Vec::new(),
    }};
    
    state.allowances.insert((owner, spender), amount);
    borsh::to_vec(&state).unwrap_or_default()
}}

#[no_mangle]
pub extern "C" fn transfer_from(
    state_ptr: *const u8,
    state_len: i32,
    spender_ptr: *const u8,
    spender_len: i32,
    from_ptr: *const u8,
    from_len: i32,
    to_ptr: *const u8,
    to_len: i32,
    amount: u64
) -> Vec<u8> {{
    let state_bytes = match read_params(state_ptr, state_len) {{
        Ok(s) => s,
        Err(_) => return Vec::new(),
    }};
    let spender = match read_params(spender_ptr, spender_len) {{
        Ok(s) => s,
        Err(_) => return Vec::new(),
    }};
    let from = match read_params(from_ptr, from_len) {{
        Ok(f) => f,
        Err(_) => return Vec::new(),
    }};
    let to = match read_params(to_ptr, to_len) {{
        Ok(t) => t,
        Err(_) => return Vec::new(),
    }};
    
    let mut state: TokenState = match TokenState::try_from_slice(&state_bytes) {{
        Ok(s) => s,
        Err(_) => return Vec::new(),
    }};
    
    // Check allowance
    let allowance = state.allowances.get(&(from.clone(), spender.clone())).copied().unwrap_or(0);
    if allowance < amount {{
        return Vec::new();
    }}
    
    // Check balance
    let from_balance = state.balances.get(&from).copied().unwrap_or(0);
    if from_balance < amount {{
        return Vec::new();
    }}
    
    // Transfer
    state.balances.insert(from.clone(), from_balance - amount);
    let to_balance = state.balances.get(&to).copied().unwrap_or(0);
    state.balances.insert(to, to_balance + amount);
    
    // Update allowance
    state.allowances.insert((from, spender), allowance - amount);
    
    borsh::to_vec(&state).unwrap_or_default()
}}

#[no_mangle]
pub extern "C" fn mint(
    state_ptr: *const u8,
    state_len: i32,
    caller_ptr: *const u8,
    caller_len: i32,
    recipient_ptr: *const u8,
    recipient_len: i32,
    amount: u64
) -> Vec<u8> {{
    let state_bytes = match read_params(state_ptr, state_len) {{
        Ok(s) => s,
        Err(_) => return Vec::new(),
    }};
    let caller = match read_params(caller_ptr, caller_len) {{
        Ok(c) => c,
        Err(_) => return Vec::new(),
    }};
    let recipient = match read_params(recipient_ptr, recipient_len) {{
        Ok(r) => r,
        Err(_) => return Vec::new(),
    }};
    
    let mut state: TokenState = match TokenState::try_from_slice(&state_bytes) {{
        Ok(s) => s,
        Err(_) => return Vec::new(),
    }};
    
    // Only owner can mint
    if caller != state.owner {{
        return Vec::new();
    }}
    
    let recipient_balance = state.balances.get(&recipient).copied().unwrap_or(0);
    state.balances.insert(recipient, recipient_balance + amount);
    state.total_supply += amount;
    
    borsh::to_vec(&state).unwrap_or_default()
}}
"#, total_supply = total_supply)
    }
    
    fn generate_nft(_contract: &EnglishContract) -> String {
        // TODO: Implement NFT template
        String::from("// NFT template coming soon")
    }
    
    fn generate_escrow(_contract: &EnglishContract) -> String {
        // TODO: Implement Escrow template
        String::from("// Escrow template coming soon")
    }
    
    fn generate_staking(_contract: &EnglishContract) -> String {
        // TODO: Implement Staking template
        String::from("// Staking template coming soon")
    }
    
    fn generate_dao(_contract: &EnglishContract) -> String {
        // TODO: Implement DAO template
        String::from("// DAO template coming soon")
    }
    
    fn generate_multisig(_contract: &EnglishContract) -> String {
        // TODO: Implement MultiSig template
        String::from("// MultiSig template coming soon")
    }
    
    fn generate_vesting(_contract: &EnglishContract) -> String {
        // TODO: Implement Vesting template
        String::from("// Vesting template coming soon")
    }
}
