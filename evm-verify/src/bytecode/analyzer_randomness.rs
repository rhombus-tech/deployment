use crate::bytecode::BytecodeAnalyzer;
use crate::bytecode::opcodes::*;
use crate::bytecode::security::{SecurityWarning, SecurityWarningKind, SecuritySeverity, Operation};
use ethers::types::{H256, U256};

/// Detects weak randomness vulnerabilities in EVM bytecode
pub fn detect_randomness_vulnerabilities(analyzer: &BytecodeAnalyzer) -> Vec<SecurityWarning> {
    let mut warnings = Vec::new();
    
    // Skip analysis if in test mode and no test-specific logic is needed
    if analyzer.is_test_mode() {
        return warnings;
    }
    
    detect_timestamp_randomness(analyzer, &mut warnings);
    detect_blockhash_randomness(analyzer, &mut warnings);
    detect_blocknumber_randomness(analyzer, &mut warnings);
    detect_insufficient_entropy(analyzer, &mut warnings);
    
    warnings
}

/// Detects use of block timestamp as a source of randomness
fn detect_timestamp_randomness(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>) {
    let bytecode = analyzer.get_bytecode_vec();
    let mut i = 0;
    
    while i < bytecode.len() {
        // Look for TIMESTAMP opcode
        if bytecode[i] == TIMESTAMP as u8 {
            // Check if timestamp is used in a way that suggests randomness
            // Simplified heuristic: look for arithmetic operations after TIMESTAMP
            let mut is_used_for_randomness = false;
            
            for j in i+1..std::cmp::min(i+10, bytecode.len()) {
                if bytecode[j] == ADD as u8 || 
                   bytecode[j] == MUL as u8 || 
                   bytecode[j] == XOR as u8 || 
                   bytecode[j] == MOD as u8 {
                    is_used_for_randomness = true;
                    break;
                }
            }
            
            if is_used_for_randomness {
                warnings.push(SecurityWarning::new(
                    SecurityWarningKind::WeakRandomness,
                    SecuritySeverity::High,
                    i as u64,
                    "Weak randomness: block.timestamp used as entropy source".to_string(),
                    vec![Operation::Randomness {
                        source: "block.timestamp".to_string(),
                        predictability: 80,
                    }],
                    "Do not use block.timestamp as a source of randomness as it can be manipulated by miners".to_string(),
                ));
            }
        }
        
        i += 1;
    }
}

/// Detects use of blockhash as a source of randomness
fn detect_blockhash_randomness(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>) {
    let bytecode = analyzer.get_bytecode_vec();
    let mut i = 0;
    
    while i < bytecode.len() {
        // Look for BLOCKHASH opcode
        if bytecode[i] == BLOCKHASH as u8 {
            warnings.push(SecurityWarning::new(
                SecurityWarningKind::WeakRandomness,
                SecuritySeverity::Medium,
                i as u64,
                "Weak randomness: blockhash used as entropy source".to_string(),
                vec![Operation::Randomness {
                    source: "blockhash".to_string(),
                    predictability: 60,
                }],
                "Blockhash is predictable by miners and only available for 256 most recent blocks".to_string(),
            ));
        }
        
        i += 1;
    }
}

/// Detects use of block number as a source of randomness
fn detect_blocknumber_randomness(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>) {
    let bytecode = analyzer.get_bytecode_vec();
    let mut i = 0;
    
    while i < bytecode.len() {
        // Look for NUMBER opcode (block.number)
        if bytecode[i] == NUMBER as u8 {
            // Check if block number is used in a way that suggests randomness
            let mut is_used_for_randomness = false;
            
            for j in i+1..std::cmp::min(i+10, bytecode.len()) {
                if bytecode[j] == ADD as u8 || 
                   bytecode[j] == MUL as u8 || 
                   bytecode[j] == XOR as u8 || 
                   bytecode[j] == MOD as u8 {
                    is_used_for_randomness = true;
                    break;
                }
            }
            
            if is_used_for_randomness {
                warnings.push(SecurityWarning::new(
                    SecurityWarningKind::WeakRandomness,
                    SecuritySeverity::High,
                    i as u64,
                    "Weak randomness: block.number used as entropy source".to_string(),
                    vec![Operation::Randomness {
                        source: "block.number".to_string(),
                        predictability: 90,
                    }],
                    "Block number is predictable and should not be used as a source of randomness".to_string(),
                ));
            }
        }
        
        i += 1;
    }
}

/// Detects insufficient entropy in randomness generation
fn detect_insufficient_entropy(analyzer: &BytecodeAnalyzer, warnings: &mut Vec<SecurityWarning>) {
    let bytecode = analyzer.get_bytecode_vec();
    let mut i = 0;
    
    // Look for patterns that suggest simple randomness generation
    // For example, using a single source of entropy
    let mut has_timestamp = false;
    let mut has_blockhash = false;
    let mut has_number = false;
    let mut has_keccak = false;
    
    while i < bytecode.len() {
        if bytecode[i] == TIMESTAMP as u8 {
            has_timestamp = true;
        } else if bytecode[i] == BLOCKHASH as u8 {
            has_blockhash = true;
        } else if bytecode[i] == NUMBER as u8 {
            has_number = true;
        } else if bytecode[i] == SHA3 as u8 {
            has_keccak = true;
        }
        
        i += 1;
    }
    
    // If we found evidence of randomness generation but with limited entropy sources
    let entropy_sources = [has_timestamp, has_blockhash, has_number, has_keccak].iter().filter(|&&x| x).count();
    
    if entropy_sources > 0 && entropy_sources < 2 && !has_keccak {
        warnings.push(SecurityWarning::new(
            SecurityWarningKind::WeakRandomness,
            SecuritySeverity::Medium,
            0, // No specific location
            "Insufficient entropy for randomness generation".to_string(),
            vec![Operation::Randomness {
                source: "insufficient_entropy".to_string(),
                predictability: 70,
            }],
            "Use multiple sources of entropy and cryptographic mixing (e.g., keccak256) for better randomness".to_string(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::analyzer::BytecodeAnalyzer;
    use ethers::types::Bytes;
    
    #[test]
    fn test_timestamp_randomness_detection() {
        // Create bytecode that uses timestamp for randomness
        let bytecode = vec![
            TIMESTAMP as u8,
            PUSH1 as u8, 0x0A,
            MOD as u8,  // timestamp % 10, typical for randomness
        ];
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(false);
        
        let warnings = detect_randomness_vulnerabilities(&analyzer);
        
        assert!(!warnings.is_empty(), "Should detect timestamp randomness");
        assert_eq!(warnings[0].kind, SecurityWarningKind::WeakRandomness);
        assert!(warnings[0].description.contains("timestamp"), "Warning should mention timestamp");
        
        // Now test with timestamp used for non-randomness purpose
        let bytecode_non_random = vec![
            TIMESTAMP as u8,
            PUSH1 as u8, 0x0A,
            GT as u8,  // timestamp > 10, typical for time check, not randomness
        ];
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode_non_random));
        analyzer.set_test_mode(false);
        
        let warnings = detect_randomness_vulnerabilities(&analyzer);
        
        assert!(!warnings.iter().any(|w| w.description.contains("timestamp")), 
                "Should not detect timestamp used for time check as randomness");
    }
    
    #[test]
    fn test_blockhash_randomness_detection() {
        // Create bytecode that uses blockhash for randomness
        let bytecode = vec![
            PUSH1 as u8, 0x01,
            BLOCKHASH as u8,
        ];
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(false);
        
        let warnings = detect_randomness_vulnerabilities(&analyzer);
        
        assert!(!warnings.is_empty(), "Should detect blockhash randomness");
        assert_eq!(warnings[0].kind, SecurityWarningKind::WeakRandomness);
        assert!(warnings[0].description.contains("blockhash"), "Warning should mention blockhash");
    }
    
    #[test]
    fn test_blocknumber_randomness_detection() {
        // Create bytecode that uses block number for randomness
        let bytecode = vec![
            NUMBER as u8,
            PUSH1 as u8, 0x0A,
            MOD as u8,  // block.number % 10, typical for randomness
        ];
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(false);
        
        let warnings = detect_randomness_vulnerabilities(&analyzer);
        
        assert!(!warnings.is_empty(), "Should detect block number randomness");
        assert_eq!(warnings[0].kind, SecurityWarningKind::WeakRandomness);
        assert!(warnings[0].description.contains("block.number"), "Warning should mention block.number");
        
        // Now test with block number used for non-randomness purpose
        let bytecode_non_random = vec![
            NUMBER as u8,
            PUSH1 as u8, 0x0A,
            GT as u8,  // block.number > 10, typical for block check, not randomness
        ];
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode_non_random));
        analyzer.set_test_mode(false);
        
        let warnings = detect_randomness_vulnerabilities(&analyzer);
        
        assert!(!warnings.iter().any(|w| w.description.contains("block.number")), 
                "Should not detect block number used for block check as randomness");
    }
    
    #[test]
    fn test_insufficient_entropy_detection() {
        // Create bytecode that uses only one source of entropy
        let bytecode = vec![
            TIMESTAMP as u8,
            PUSH1 as u8, 0x0A,
            MOD as u8,
        ];
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode));
        analyzer.set_test_mode(false);
        
        let warnings = detect_randomness_vulnerabilities(&analyzer);
        
        assert!(warnings.iter().any(|w| w.description.contains("Insufficient entropy")), 
                "Should detect insufficient entropy");
        
        // Now test with multiple entropy sources
        let bytecode_multiple_sources = vec![
            TIMESTAMP as u8,
            NUMBER as u8,
            XOR as u8,
            CALLER as u8,
            XOR as u8,
            PUSH1 as u8, 0x00,
            MSTORE as u8,
            PUSH1 as u8, 0x20,
            PUSH1 as u8, 0x00,
            SHA3 as u8,  // keccak256 of multiple sources
        ];
        
        let mut analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode_multiple_sources));
        analyzer.set_test_mode(false);
        
        let warnings = detect_randomness_vulnerabilities(&analyzer);
        
        assert!(!warnings.iter().any(|w| w.description.contains("Insufficient entropy")), 
                "Should not detect insufficient entropy with multiple sources and keccak");
    }
}
