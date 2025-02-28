// External Call Analyzer
//
// This module provides functionality to detect external calls in EVM bytecode.
// External calls are important for cross-chain communication analysis.

use crate::bytecode::types::{AnalysisResults, ExternalCall};
use crate::bytecode::opcodes::{Opcode, CALL, STATICCALL, CALLCODE, DELEGATECALL};
use ethers::types::{Address, Bytes, U256};
use anyhow::Result;

/// External call detector
pub struct ExternalCallDetector;

impl ExternalCallDetector {
    /// Detect external calls in bytecode
    pub fn detect(bytecode: &[u8], results: &mut AnalysisResults) -> Result<()> {
        // Initialize external calls vector if empty
        if results.external_calls.is_empty() {
            results.external_calls = Vec::new();
        }
        
        // Scan bytecode for call opcodes
        for i in 0..bytecode.len() {
            match bytecode[i] {
                CALL => {
                    // Found a CALL opcode
                    results.external_calls.push(ExternalCall {
                        offset: i,
                        target: None, // Would need runtime analysis to determine
                        value: U256::zero(), // Default value
                        data: Bytes::default(),
                        gas: U256::zero(),
                        call_type: "CALL".to_string(),
                        is_known_contract: false,
                        is_potential_bridge: Self::is_potential_bridge(&bytecode[i+1..]),
                    });
                    
                    // Add a warning about external call
                    if Self::is_potential_bridge(&bytecode[i+1..]) {
                        results.warnings.push(format!(
                            "Potential cross-chain bridge call detected at offset {}. This may require special handling on L2 chains.",
                            i
                        ));
                    }
                },
                STATICCALL => {
                    // Found a STATICCALL opcode
                    results.external_calls.push(ExternalCall {
                        offset: i,
                        target: None,
                        value: U256::zero(), // STATICCALL has no value
                        data: Bytes::default(),
                        gas: U256::zero(),
                        call_type: "STATICCALL".to_string(),
                        is_known_contract: false,
                        is_potential_bridge: false, // STATICCALL can't be a bridge (no state changes)
                    });
                },
                CALLCODE => {
                    // Found a CALLCODE opcode
                    results.external_calls.push(ExternalCall {
                        offset: i,
                        target: None,
                        value: U256::zero(),
                        data: Bytes::default(),
                        gas: U256::zero(),
                        call_type: "CALLCODE".to_string(),
                        is_known_contract: false,
                        is_potential_bridge: false,
                    });
                },
                DELEGATECALL => {
                    // DELEGATECALL is already tracked in delegate_calls
                    // Just add to external_calls for completeness
                    results.external_calls.push(ExternalCall {
                        offset: i,
                        target: None,
                        value: U256::zero(), // DELEGATECALL has no value
                        data: Bytes::default(),
                        gas: U256::zero(),
                        call_type: "DELEGATECALL".to_string(),
                        is_known_contract: false,
                        is_potential_bridge: false,
                    });
                },
                _ => continue,
            }
        }
        
        Ok(())
    }
    
    /// Determine if a call might be to a bridge contract
    /// This is a heuristic based on common patterns in bridge contracts
    fn is_potential_bridge(bytecode: &[u8]) -> bool {
        // Look for patterns that might indicate a bridge
        // This is a simplified heuristic and would need more sophisticated analysis
        // for accurate detection
        
        // Check for large value transfers
        let mut has_large_value = false;
        
        // Check for specific function signatures common in bridges
        // For example, many bridges use "transfer" or "bridgeAsset" functions
        let mut has_bridge_signature = false;
        
        // Simple pattern matching for bridge-like behavior
        for i in 0..std::cmp::min(50, bytecode.len()) {
            // Check for PUSH32 followed by specific bytes that might be bridge signatures
            if i + 32 < bytecode.len() && bytecode[i] == 0x7F { // PUSH32
                // Check for "transfer" signature (0xa9059cbb)
                if bytecode[i+1] == 0xa9 && bytecode[i+2] == 0x05 && 
                   bytecode[i+3] == 0x9c && bytecode[i+4] == 0xbb {
                    has_bridge_signature = true;
                }
                
                // Check for "transferFrom" signature (0x23b872dd)
                if bytecode[i+1] == 0x23 && bytecode[i+2] == 0xb8 && 
                   bytecode[i+3] == 0x72 && bytecode[i+4] == 0xdd {
                    has_bridge_signature = true;
                }
            }
        }
        
        has_large_value || has_bridge_signature
    }
}
