use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::HashMap;

#[derive(BorshSerialize, BorshDeserialize)]
struct State {
    balances: HashMap<Vec<u8>, u64>,
    allowances: HashMap<Vec<u8>, HashMap<Vec<u8>, u64>>,
    total_supply: u64,
    owner: Vec<u8>,
}

#[no_mangle]
pub extern "C" fn initialize() -> Vec<u8> {
    let mut state = State {
        balances: HashMap::new(),
        allowances: HashMap::new(),
        total_supply: 1_000_000,
        owner: Vec::new(),
    };

    state.owner = Vec::from([0x01, 0x02, 0x03]);
    state.balances.insert(state.owner.clone(), state.total_supply);

    state.serialize()
}

#[no_mangle]
pub extern "C" fn transfer(recipient: *const u8, recipient_len: i32, amount: u64) -> Vec<u8> {
    let mut state: State = State::deserialize(&Vec::from_raw_parts(recipient, recipient_len as usize, recipient_len as usize)).unwrap();
    let sender = state.owner.clone();

    if state.balances.get(&sender).unwrap() < &amount {
        return Vec::new();
    }

    if amount == 0 || recipient_len == 0 {
        return Vec::new();
    }

    state.balances.insert(sender, state.balances.get(&sender).unwrap() - amount);
    state.balances.insert(Vec::from_raw_parts(recipient, recipient_len as usize, recipient_len as usize), state.balances.get(&Vec::from_raw_parts(recipient, recipient_len as usize, recipient_len as usize)).unwrap_or(&0) + amount);

    state.serialize()
}

#[no_mangle]
pub extern "C" fn balance_of(account: *const u8, account_len: i32) -> Vec<u8> {
    let state: State = State::deserialize(&Vec::from_raw_parts(account, account_len as usize, account_len as usize)).unwrap();
    state.balances.get(&Vec::from_raw_parts(account, account_len as usize, account_len as usize)).cloned().unwrap_or(0).serialize()
}

#[no_mangle]
pub extern "C" fn approve(spender: *const u8, spender_len: i32, amount: u64) -> Vec<u8> {
    let mut state: State = State::deserialize(&Vec::from_raw_parts(spender, spender_len as usize, spender_len as usize)).unwrap();
    let owner = state.owner.clone();

    if spender_len == 0 {
        return Vec::new();
    }

    state.allowances.entry(owner).or_insert(HashMap::new()).insert(Vec::from_raw_parts(spender, spender_len as usize, spender_len as usize), amount);

    state.serialize()
}

#[no_mangle]
pub extern "C" fn transfer_from(from: *const u8, from_len: i32, to: *const u8, to_len: i32, amount: u64) -> Vec<u8> {
    let mut state: State = State::deserialize(&Vec::from_raw_parts(from, from_len as usize, from_len as usize)).unwrap();
    let sender = state.owner.clone();

    if state.balances.get(&Vec::from_raw_parts(from, from_len as usize, from_len as usize)).unwrap() < &amount {
        return Vec::new();
    }

    if state.allowances.get(&Vec::from_raw_parts(from, from_len as usize, from_len as usize)).unwrap().get(&sender).unwrap() < &amount {
        return Vec::new();
    }

    if to_len == 0 {
        return Vec::new();
    }

    state.balances.insert(Vec::from_raw_parts(from, from_len as usize, from_len as usize), state.balances.get(&Vec::from_raw_parts(from, from_len as usize, from_len as usize)).unwrap() - amount);
    state.balances.insert(Vec::from_raw_parts(to, to_len as usize, to_len as usize), state.balances.get(&Vec::from_raw_parts(to, to_len as usize, to_len as usize)).unwrap_or(&0) + amount);
    state.allowances.get_mut(&Vec::from_raw_parts(from, from_len as usize, from_len as usize)).unwrap().insert(sender, state.allowances.get(&Vec::from_raw_parts(from, from_len as usize, from_len as usize)).unwrap().get(&sender).unwrap() - amount);

    state.serialize()
}

#[no_mangle]
pub extern "C" fn mint(recipient: *const u8, recipient_len: i32, amount: u64) -> Vec<u8> {
    let mut state: State = State::deserialize(&Vec::from_raw_parts(recipient, recipient_len as usize, recipient_len as usize)).unwrap();

    if amount == 0 {
        return Vec::new();
    }

    if state.owner != Vec::from_raw_parts(recipient, recipient_len as usize, recipient_len as usize) {
        return Vec::new();
    }

    state.balances.insert(Vec::from_raw_parts(recipient, recipient_len as usize, recipient_len as usize), state.balances.get(&Vec::from_raw_parts(recipient, recipient_len as usize, recipient_len as usize)).unwrap_or(&0) + amount);
    state.total_supply += amount;

    state.serialize()
}