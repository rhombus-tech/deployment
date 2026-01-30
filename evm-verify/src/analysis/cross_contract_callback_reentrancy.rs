/// Cross-Contract Callback Reentrancy Analyzer
/// 
/// YOUR ADVANTAGE: Detects read-only reentrancy via callbacks
/// 
/// Real Exploit: Curve read-only reentrancy pattern
/// Pattern: Contract A calls B → B has callback → Callback calls A.view() → Stale state read
/// Example: Vyper reentrancy lock doesn't protect view functions

use ethers::types::H160;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractCallbackReentrancy {
    pub vulnerability_type: String,
    pub severity: String,
    pub callback_chain: Vec<H160>,  // A → B → callback → A.view()
    pub vulnerable_view_function: Option<String>,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractCallbackReentrancyAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractCallbackReentrancyAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractCallbackReentrancy> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Find contracts with callbacks (fallback, receive, hooks)
        let callback_contracts = self.find_callback_contracts(&contracts);
        
        // For each contract that calls a callback contract
        for (caller_addr, caller_bytecode) in contracts.iter() {
            let targets = self.protocol.get_call_targets(caller_addr);
            
            for target in &targets {
                if callback_contracts.contains(target) {
                    // Check if callback can call back to caller's view functions
                    if self.has_view_functions(caller_bytecode) {
                        vulnerabilities.push(CrossContractCallbackReentrancy {
                            vulnerability_type: "Cross-Contract Callback Reentrancy".to_string(),
                            severity: "High".to_string(),
                            callback_chain: vec![*caller_addr, *target, *caller_addr],
                            vulnerable_view_function: Some("view/pure functions".to_string()),
                            description: format!(
                                "Contract {:?} calls {:?} which has callback → can reenter {:?}'s view functions with stale state",
                                caller_addr, target, caller_addr
                            ),
                            exploit_scenario: format!(
                                "READ-ONLY REENTRANCY ATTACK:\n\
                                 1. Contract A calls Contract B (has callback/hook)\n\
                                 2. B's callback executes during A's state change\n\
                                 3. Callback calls A.viewFunction() → reads STALE state\n\
                                 4. Use stale state reading to manipulate dependent protocols\n\
                                 \n\
                                 Real example: Curve Vyper reentrancy - view functions unprotected!\n\
                                 Path: Vault → Curve.remove_liquidity() → callback → Vault.totalAssets() [STALE!]"
                            ),
                            remediation: "Protect view functions with reentrancy guards or ensure state is consistent before external calls".to_string(),
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_callback_contracts(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        // Fallback/receive functions often have these patterns
        let fallback_pattern = [0x5b, 0x60, 0x00, 0x52]; // fallback pattern
        let receive_pattern = [0x36, 0x10, 0x15, 0x60];  // receive pattern (padded to 4 bytes)
        
        contracts.iter()
            .filter(|(_, bc)| {
                bc.windows(4).any(|w| w == &fallback_pattern) ||
                bc.windows(4).any(|w| w == &receive_pattern) ||
                bc.contains(&0x5B) // JUMPDEST (fallback indicator)
            })
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    fn has_view_functions(&self, bytecode: &[u8]) -> bool {
        // STATICCALL opcode indicates view/pure functions
        bytecode.contains(&0xFA) // STATICCALL
    }
}

impl CrossContractCallbackReentrancy {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::CrossContractReentrancy,
            severity: SecuritySeverity::High,
            description: self.description.clone(),
            call_path: self.callback_chain.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
