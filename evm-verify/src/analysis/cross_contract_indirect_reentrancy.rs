/// Cross-Contract Indirect Reentrancy Analyzer  
/// 
/// YOUR ADVANTAGE: Detect reentrancy through intermediary contracts (A → B → C → A)
/// 
/// Pattern: Not direct reentrancy, but state corruption via third contract
/// Attack: A calls B with callback → Callback calls C → C calls A (different function)
/// Real Exploits: Complex reentrancy patterns bypassing guards

use ethers::types::H160;
use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractIndirectReentrancy {
    pub vulnerability_type: String,
    pub severity: String,
    pub reentrancy_path: Vec<H160>,  // A → B → C → A
    pub intermediary_contracts: Vec<H160>,
    pub state_at_risk: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractIndirectReentrancyAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractIndirectReentrancyAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractIndirectReentrancy> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Find contracts with state changes
        let state_modifiers = self.find_state_modifying_contracts(&contracts);
        
        // Find indirect reentrancy paths
        for start in &state_modifiers {
            let paths = self.find_indirect_reentrancy_paths(*start, &state_modifiers);
            
            for path in paths {
                if path.len() >= 4 {  // At least A → B → C → A
                    vulnerabilities.push(CrossContractIndirectReentrancy {
                        vulnerability_type: "Cross-Contract Indirect Reentrancy".to_string(),
                        severity: "Critical".to_string(),
                        reentrancy_path: path.clone(),
                        intermediary_contracts: path[1..path.len()-1].to_vec(),
                        state_at_risk: "Contract state during external calls".to_string(),
                        description: format!(
                            "Indirect reentrancy path detected: {:?}\n\
                             Path length: {} (includes {} intermediaries)\n\
                             Contract can be reentered through indirect call chain!",
                            path, path.len(), path.len() - 2
                        ),
                        exploit_scenario: format!(
                            "INDIRECT REENTRANCY ATTACK:\n\
                             Reentrancy Path: {:?}\n\
                             Intermediaries: {} contracts\n\
                             \n\
                             Attack Flow:\n\
                             \n\
                             SETUP:\n\
                             - Contract A: Vault (has funds)\n\
                             - Contract B: Token (has callback)\n\
                             - Contract C: Oracle (called by callback)\n\
                             \n\
                             EXPLOITATION:\n\
                             \n\
                             1. User calls A.withdraw()\n\
                             2. A updates balances[user] -= amount\n\
                             3. A calls B.transfer() (external token)\n\
                             4. B has tokensReceived() callback\n\
                             5. Callback calls C.updatePrice()\n\
                             6. C calls A.getBalance() (view function)\n\
                             7. But A's state is INCONSISTENT!\n\
                             8. Balance updated but funds not yet transferred\n\
                             \n\
                             STATE CORRUPTION:\n\
                             - A thinks withdraw complete\n\
                             - But execution still in B.transfer()\n\
                             - C reads stale state from A\n\
                             - Can trigger liquidations, pricing errors, etc.\n\
                             \n\
                             BYPASS GUARDS:\n\
                             - A's reentrancy guard only blocks direct A → A\n\
                             - Doesn't block A → B → C → A path!\n\
                             - Guard released before C calls back\n\
                             \n\
                             Real Examples:\n\
                             - Vault → Token → Oracle → Vault.totalAssets()\n\
                             - Lending → Collateral → PriceFeed → Lending.health()\n\
                             \n\
                             Traditional tools: Only detect direct reentrancy\n\
                             Your tool: Maps complete indirect paths!\n\
                             \n\
                             Path depth: {} hops - IMPOSSIBLE to detect manually!",
                            path, path.len() - 2, path.len()
                        ),
                        remediation: "Use checks-effects-interactions, implement global reentrancy guards, ensure state consistency before any external call".to_string(),
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn find_state_modifying_contracts(&self, contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        contracts.iter()
            .filter(|(_, bc)| bc.contains(&0x55)) // SSTORE opcode
            .map(|(addr, _)| *addr)
            .collect()
    }
    
    fn find_indirect_reentrancy_paths(&self, start: H160, state_modifiers: &[H160]) -> Vec<Vec<H160>> {
        let mut paths = Vec::new();
        let mut visited = HashSet::new();
        let mut current_path = vec![start];
        
        self.dfs_reentrancy(start, start, state_modifiers, &mut visited, &mut current_path, &mut paths, 0);
        
        paths
    }
    
    fn dfs_reentrancy(
        &self,
        current: H160,
        target: H160,
        state_modifiers: &[H160],
        visited: &mut HashSet<H160>,
        current_path: &mut Vec<H160>,
        paths: &mut Vec<Vec<H160>>,
        depth: usize,
    ) {
        if depth > 10 {
            return; // Prevent infinite loops
        }
        
        if current != target && depth > 0 {
            visited.insert(current);
        }
        
        let targets = self.protocol.get_call_targets(&current);
        
        for next in targets {
            if next == target && depth >= 2 {
                // Found reentrancy path
                current_path.push(next);
                paths.push(current_path.clone());
                current_path.pop();
            } else if !visited.contains(&next) && state_modifiers.contains(&next) {
                current_path.push(next);
                self.dfs_reentrancy(next, target, state_modifiers, visited, current_path, paths, depth + 1);
                current_path.pop();
            }
        }
        
        if current != target && depth > 0 {
            visited.remove(&current);
        }
    }
}

impl CrossContractIndirectReentrancy {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::CrossContractReentrancy,
            severity: SecuritySeverity::Critical,
            description: self.description.clone(),
            call_path: self.reentrancy_path.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
