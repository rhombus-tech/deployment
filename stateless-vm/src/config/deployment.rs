
// Auto-generated deployment configuration
// Generated at: 2025-07-09T10:28:20.137Z

use ethers::types::Address;
use std::str::FromStr;

pub const VERIFIED_ATOMIC_EXECUTOR_ADDRESS: &str = "0x59b670e9fA9D0A427751Af201D676719a970857b";
pub const PCC_VERIFIER_BRIDGE_ADDRESS: &str = "0x68B1D87F95878fE05B998F19b66F4baba5De1aed";
pub const ZODA_VERIFIER_ADDRESS: &str = "0x9A9f2CCfdE556A7E9Ff0848998Aa4a0CFD8863AE";

pub fn get_atomic_executor_address() -> Address {
    Address::from_str(VERIFIED_ATOMIC_EXECUTOR_ADDRESS).unwrap()
}

pub fn get_pcc_verifier_address() -> Address {
    Address::from_str(PCC_VERIFIER_BRIDGE_ADDRESS).unwrap()
}
