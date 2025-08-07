// External Call Analyzer
//
// This module provides functionality to detect and analyze external calls in EVM bytecode.
// External calls include CALL, STATICCALL, CALLCODE, and DELEGATECALL opcodes.
// This analyzer focuses on identifying external call patterns and potential security issues.

use crate::bytecode::types::{AnalysisResults, ExternalCall};
use crate::bytecode::opcodes::{CALL, STATICCALL, CALLCODE, DELEGATECALL};
use ethers::types::{Bytes, U256};
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
                        is_potential_bridge: Self::is_potential_cross_chain_call(&bytecode[i+1..]),
                    });
                    
                    // Add a warning about external call
                    if Self::is_potential_cross_chain_call(&bytecode[i+1..]) {
                        results.warnings.push(format!(
                            "Potential cross-chain call detected at offset {}. Review for L2 compatibility.",
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
    
    /// Simple heuristic based on common cross-chain function signatures
    fn is_potential_cross_chain_call(bytecode: &[u8]) -> bool {
        Self::has_cross_chain_signatures(bytecode) || Self::has_bridge_patterns(bytecode)
    }
    
    /// Check for cross-chain function signatures
    fn has_cross_chain_signatures(bytecode: &[u8]) -> bool {
        let signatures = [
            [0x23, 0xb8, 0x72, 0xdd], // deposit
            [0x2e, 0x1a, 0x7d, 0x4d], // withdraw  
            [0x5d, 0x35, 0x9f, 0xbd], // bridge
            [0x32, 0xb7, 0x00, 0x6d], // relayMessage
            [0x4c, 0x69, 0x3a, 0x83], // crossChainTransfer
        ];
        
        for i in 0..(bytecode.len().saturating_sub(4)) {
            if i + 4 <= bytecode.len() {
                let sig_bytes = [bytecode[i], bytecode[i+1], bytecode[i+2], bytecode[i+3]];
                if signatures.contains(&sig_bytes) {
                    return true;
                }
            }
        }
        false
    }
    

    
    /// Check for simple bridge patterns
    fn has_bridge_patterns(bytecode: &[u8]) -> bool {
        // Look for common bridge-related opcodes and patterns
        let mut has_large_transfers = false;
        let mut has_merkle_proofs = false;
        
        for i in 0..(bytecode.len().saturating_sub(4)) {
            // Check for large value operations (common in bridge contracts)
            if bytecode[i] == 0x34 { // CALLVALUE
                has_large_transfers = true;
            }
            
            // Check for hash operations (Merkle proof validation)
            if bytecode[i] == 0x20 { // KECCAK256
                has_merkle_proofs = true;
            }
        }
        
        has_large_transfers && has_merkle_proofs
    }
}
