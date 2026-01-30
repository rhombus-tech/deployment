// Contract metadata parser - extracts Solidity version from bytecode CBOR metadata
// This enables precise detection of Solidity 0.8+ contracts with automatic overflow protection

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractMetadata {
    pub solidity_version: Option<String>,
    pub has_metadata: bool,
    pub has_solc_0_8_plus: bool,
}

pub struct MetadataParser;

impl MetadataParser {
    /// Extract contract metadata from bytecode
    /// Solidity compiler appends CBOR-encoded metadata at the end:
    /// Format: <bytecode> 0xa2 0x64 'i' 'p' 'f' 's' ... 0x00 0x33 <length>
    /// The metadata contains the Solidity version
    pub fn parse(bytecode: &[u8]) -> ContractMetadata {
        if bytecode.len() < 10 {
            return ContractMetadata {
                solidity_version: None,
                has_metadata: false,
                has_solc_0_8_plus: false,
            };
        }
        
        // Solidity metadata ends with: 0xa2 0x64 'i' 'p' 'f' 's' ...
        // Or newer format: 0xa2 0x65 'b' 'z' 'z' 'r' '0' / '1'
        // Last 2 bytes are length (big-endian)
        
        // Try to find metadata marker from the end
        let metadata_length = Self::find_metadata_length(bytecode);
        
        if let Some(length) = metadata_length {
            if length < bytecode.len() {
                let metadata_start = bytecode.len() - length;
                let metadata_bytes = &bytecode[metadata_start..];
                
                // Try to extract Solidity version from metadata
                let version = Self::extract_solidity_version(metadata_bytes);
                let is_0_8_plus = version.as_ref()
                    .map(|v| Self::is_version_0_8_or_higher(v))
                    .unwrap_or(false);
                
                return ContractMetadata {
                    solidity_version: version,
                    has_metadata: true,
                    has_solc_0_8_plus: is_0_8_plus,
                };
            }
        }
        
        // No metadata found - try heuristic detection
        // Solidity 0.8+ has characteristic patterns
        let likely_0_8_plus = Self::detect_solc_0_8_heuristics(bytecode);
        
        ContractMetadata {
            solidity_version: None,
            has_metadata: false,
            has_solc_0_8_plus: likely_0_8_plus,
        }
    }
    
    fn find_metadata_length(bytecode: &[u8]) -> Option<usize> {
        if bytecode.len() < 4 {
            return None;
        }
        
        // Last 2 bytes encode metadata length
        let len_bytes = &bytecode[bytecode.len() - 2..];
        let length = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
        
        // Sanity check: metadata should be reasonable size (< 1/3 of contract)
        if length < 10 || length > bytecode.len() / 3 {
            return None;
        }
        
        // Check for CBOR metadata marker (0xa2 = CBOR map with 2 items)
        let metadata_start = bytecode.len() - length;
        if metadata_start > 0 && bytecode[metadata_start] == 0xa2 {
            return Some(length);
        }
        
        // Try alternative: 0xa1 (CBOR map with 1 item) - older format
        if metadata_start > 0 && bytecode[metadata_start] == 0xa1 {
            return Some(length);
        }
        
        None
    }
    
    fn extract_solidity_version(metadata: &[u8]) -> Option<String> {
        // Search for "solc" string in metadata (CBOR encoded)
        // Pattern: 0x64 's' 'o' 'l' 'c' <length> <version bytes>
        
        for i in 0..metadata.len().saturating_sub(10) {
            // Look for "solc" (0x64 = CBOR text string of length 4)
            if i + 5 < metadata.len() 
                && metadata[i] == 0x64 
                && metadata[i+1] == b's'
                && metadata[i+2] == b'o'
                && metadata[i+3] == b'l'
                && metadata[i+4] == b'c' {
                
                // Next byte is version string length
                if i + 6 < metadata.len() {
                    let version_len = metadata[i+5] as usize;
                    
                    // Sanity check
                    if version_len > 0 && version_len < 50 && i + 6 + version_len <= metadata.len() {
                        let version_bytes = &metadata[i+6..i+6+version_len];
                        
                        // Try to parse as UTF-8
                        if let Ok(version_str) = std::str::from_utf8(version_bytes) {
                            return Some(version_str.to_string());
                        }
                    }
                }
            }
        }
        
        None
    }
    
    fn is_version_0_8_or_higher(version: &str) -> bool {
        // Parse version string like "0.8.19+commit.abc123"
        // We only care about major.minor
        
        if let Some(major_minor) = version.split('+').next() {
            let parts: Vec<&str> = major_minor.split('.').collect();
            
            if parts.len() >= 2 {
                if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                    // 0.8.0 and higher have automatic overflow checks
                    return major == 0 && minor >= 8;
                }
            }
        }
        
        false
    }
    
    /// Heuristic detection of Solidity 0.8+ when metadata is missing
    /// 0.8+ has characteristic bytecode patterns for overflow checks
    fn detect_solc_0_8_heuristics(bytecode: &[u8]) -> bool {
        let mut overflow_check_count = 0;
        let mut arithmetic_count = 0;
        let mut panic_error_found = false;
        let mut pc = 0;
        
        // Solidity 0.8+ uses Panic(uint256) errors with specific codes:
        // 0x11 = arithmetic overflow/underflow
        // Look for: PUSH4 0x4e487b71 (Panic selector)
        for i in 0..bytecode.len().saturating_sub(10) {
            if bytecode[i] == 0x63 && i + 4 < bytecode.len() {  // PUSH4
                let selector = u32::from_be_bytes([
                    bytecode[i+1], bytecode[i+2], bytecode[i+3], bytecode[i+4]
                ]);
                if selector == 0x4e487b71 {  // Panic(uint256) selector
                    panic_error_found = true;
                    break;
                }
            }
        }
        
        // If Panic errors present, likely 0.8+ (strong signal)
        if panic_error_found {
            return true;
        }
        
        pc = 0;
        while pc < bytecode.len() {
            let opcode = bytecode[pc];
            
            // Count arithmetic operations
            if matches!(opcode, 0x01 | 0x02 | 0x03) {  // ADD, MUL, SUB
                arithmetic_count += 1;
                
                // Check for Solidity 0.8+ overflow check pattern within 20 bytes:
                // op → DUP → LT/GT → JUMPI (with optional ISZERO)
                if Self::has_solc_0_8_pattern_after(bytecode, pc) {
                    overflow_check_count += 1;
                }
            }
            
            pc += 1;
            
            // Skip PUSH data
            if opcode >= 0x60 && opcode <= 0x7F {
                let push_bytes = (opcode - 0x5F) as usize;
                pc += push_bytes;
            }
        }
        
        // If 30%+ of arithmetic ops have 0.8+ pattern, likely 0.8+
        if arithmetic_count > 5 {
            let check_rate = overflow_check_count as f32 / arithmetic_count as f32;
            return check_rate >= 0.30;
        }
        
        false
    }
    
    fn has_solc_0_8_pattern_after(bytecode: &[u8], start_pc: usize) -> bool {
        // Solidity 0.8+ specific pattern:
        // ADD/MUL/SUB → DUP1 → LT/GT → JUMPI
        // or: ADD/MUL/SUB → DUP1 → LT/GT → ISZERO → JUMPI
        
        let mut pc = start_pc + 1;
        let end_pc = (start_pc + 20).min(bytecode.len());
        let mut found_dup = false;
        let mut found_comparison = false;
        
        while pc < end_pc {
            let opcode = bytecode[pc];
            
            // DUP1 (0x80) is characteristic of 0.8+ checks
            if opcode == 0x80 {
                found_dup = true;
            }
            
            // LT (0x10) or GT (0x11) comparison
            if matches!(opcode, 0x10 | 0x11) {
                found_comparison = true;
            }
            
            // JUMPI after DUP + comparison = 0.8+ pattern
            if opcode == 0x57 && found_dup && found_comparison {
                return true;
            }
            
            pc += 1;
            
            // Skip PUSH data
            if opcode >= 0x60 && opcode <= 0x7F {
                let push_bytes = (opcode - 0x5F) as usize;
                pc += push_bytes;
            }
        }
        
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_solidity_0_8_metadata() {
        // Simulated bytecode with Solidity 0.8.19 metadata
        let mut bytecode = vec![0x60, 0x80, 0x60, 0x40]; // Some opcodes
        
        // Append CBOR metadata (simplified)
        let metadata = vec![
            0xa2, // CBOR map with 2 items
            0x64, b's', b'o', b'l', b'c', // "solc"
            0x06, b'0', b'.', b'8', b'.', b'1', b'9', // "0.8.19"
        ];
        
        let metadata_len = (metadata.len() as u16).to_be_bytes();
        bytecode.extend_from_slice(&metadata);
        bytecode.extend_from_slice(&metadata_len);
        
        let result = MetadataParser::parse(&bytecode);
        
        assert!(result.has_metadata);
        assert!(result.has_solc_0_8_plus);
    }
    
    #[test]
    fn test_parse_solidity_0_5_metadata() {
        // Simulated bytecode with Solidity 0.5.16 metadata
        let mut bytecode = vec![0x60, 0x80, 0x60, 0x40];
        
        let metadata = vec![
            0xa2,
            0x64, b's', b'o', b'l', b'c',
            0x07, b'0', b'.', b'5', b'.', b'1', b'6', b'+',
        ];
        
        let metadata_len = (metadata.len() as u16).to_be_bytes();
        bytecode.extend_from_slice(&metadata);
        bytecode.extend_from_slice(&metadata_len);
        
        let result = MetadataParser::parse(&bytecode);
        
        assert!(result.has_metadata);
        assert!(!result.has_solc_0_8_plus);
    }
    
    #[test]
    fn test_no_metadata() {
        let bytecode = vec![0x60, 0x80, 0x60, 0x40, 0x52, 0x60, 0x04];
        
        let result = MetadataParser::parse(&bytecode);
        
        assert!(!result.has_metadata);
    }
}
