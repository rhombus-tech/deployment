use std::fmt;
use ethers::types::{H256, U256, Address, Bytes};

/// Utility functions for the stateless VM implementation

/// Format bytes as hex string
pub fn format_bytes_as_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Format a H256 hash for display
pub fn format_hash(hash: &H256) -> String {
    format!("0x{}", hex::encode(hash.as_bytes()))
}

/// Format an address for display
pub fn format_address(addr: &Address) -> String {
    format!("0x{}", hex::encode(addr.as_bytes()))
}

/// Converts a U256 to a human-readable string
pub fn format_u256(value: &U256) -> String {
    value.to_string()
}

/// Extract bytes from ethereum types
pub fn extract_bytes(data: &Bytes) -> Vec<u8> {
    data.to_vec()
}

/// Pad a string to a fixed width
pub fn pad_string(s: &str, width: usize) -> String {
    if s.len() >= width {
        s.to_string()
    } else {
        let padding = " ".repeat(width - s.len());
        format!("{}{}", s, padding)
    }
}

/// Convert a hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let hex_str = if hex.starts_with("0x") {
        &hex[2..]
    } else {
        hex
    };
    
    hex::decode(hex_str)
}
