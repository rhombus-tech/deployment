/// Cross-Contract Shared State Race Condition Analyzer
/// 
/// YOUR ADVANTAGE: Detects race conditions when multiple contracts modify shared state
/// 
/// Pattern: Contract A and B both write to shared storage/token balances
/// Attack: Front-run transactions to exploit inconsistent state updates
/// Real Impact: DeFi protocols with multiple entry points

use ethers::types::H160;
use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractSharedStateRace {
    pub vulnerability_type: String,
    pub severity: String,
    pub racing_contracts: Vec<H160>,
    pub shared_state_pattern: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractSharedStateRaceAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractSharedStateRaceAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractSharedStateRace> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Find contracts that modify external state (SSTORE, external calls with state changes)
        let state_modifiers = self.find_state_modifying_contracts(&contracts);
        
        // Find shared targets (contracts/tokens that multiple contracts interact with)
        let shared_targets = self.find_shared_targets(&state_modifiers);
        
        for (target, modifiers) in shared_targets {
            if modifiers.len() >= 2 {
                // Check if modifications are unprotected (no mutex/ordering guarantees)
                let unprotected = self.check_unprotected_modifications(&modifiers, &contracts);
                
                if unprotected {
                    vulnerabilities.push(CrossContractSharedStateRace {
                        vulnerability_type: "Cross-Contract Shared State Race".to_string(),
                        severity: "High".to_string(),
                        racing_contracts: modifiers.clone(),
                        shared_state_pattern: format!("All modify {:?}", target),
                        description: format!(
                            "{} contracts can modify shared state at {:?} without synchronization:\n{:?}",
                            modifiers.len(), target, modifiers
                        ),
                        exploit_scenario: format!(
                            "SHARED STATE RACE ATTACK:\n\
                             Shared Target: {:?}\n\
                             Racing Contracts: {:?}\n\
                             \n\
                             Attack:\n\
                             1. Contract A updates shared state (e.g., totalSupply)\n\
                             2. Front-run with Contract B update to same state\n\
                             3. A's update completes with stale assumptions\n\
                             4. Result: State inconsistency, double-counting, or loss\n\
                             \n\
                             Example:\n\
                             - Vault A and Vault B both update Strategy.totalAssets\n\
                             - No mutex → one vault's accounting gets corrupted\n\
                             - Users can withdraw more than deposited!",
                            target, modifiers
                        ),
                        remediation: "Use mutexes, implement sequential ordering, or atomic batch updates across all contracts".to_string(),
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_state_modifying_contracts(&self, contracts: &HashMap<H160, &Vec<u8>>) -> HashMap<H160, Vec<H160>> {
        let mut modifiers = HashMap::new();
        
        for (addr, _) in contracts {
            let targets = self.protocol.get_call_targets(addr);
            modifiers.insert(*addr, targets);
        }
        
        modifiers
    }
    
    fn find_shared_targets(&self, modifiers: &HashMap<H160, Vec<H160>>) -> HashMap<H160, Vec<H160>> {
        let mut shared: HashMap<H160, Vec<H160>> = HashMap::new();
        
        // Find targets that multiple contracts call
        for (contract, targets) in modifiers {
            for &target in targets {
                shared.entry(target).or_insert_with(Vec::new).push(*contract);
            }
        }
        
        // Keep only targets with multiple modifiers
        shared.retain(|_, modifiers| modifiers.len() >= 2);
        shared
    }
    
    fn check_unprotected_modifications(&self, _modifiers: &[H160], contracts: &HashMap<H160, &Vec<u8>>) -> bool {
        // Check if any modifier uses mutex/lock pattern
        let lock_patterns = [
            [0x60, 0x01, 0x60, 0x00, 0x55], // Simple lock: PUSH1 1 PUSH1 0 SSTORE
        ];
        
        for modifier in _modifiers {
            if let Some(bytecode) = contracts.get(modifier) {
                let has_lock = lock_patterns.iter().any(|pattern| 
                    bytecode.windows(pattern.len()).any(|w| w == pattern)
                );
                if has_lock {
                    return false; // Protected
                }
            }
        }
        
        true // Unprotected
    }
}

impl CrossContractSharedStateRace {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::StateInconsistency,
            severity: SecuritySeverity::High,
            description: self.description.clone(),
            call_path: self.racing_contracts.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
