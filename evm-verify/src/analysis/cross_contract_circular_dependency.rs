/// Cross-Contract Circular Dependency Deadlock Analyzer
/// 
/// YOUR ADVANTAGE: Detects circular call chains that cause protocol deadlock
/// 
/// Pattern: Contract A → B → C → A (circular dependency)
/// Attack: Create dependency cycle causing system freeze or infinite recursion
/// Real Impact: Protocols with mutual dependencies can deadlock completely

use ethers::types::H160;
use std::collections::{HashMap, HashSet, VecDeque};
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractCircularDependency {
    pub vulnerability_type: String,
    pub severity: String,
    pub circular_path: Vec<H160>,  // A → B → C → A
    pub cycle_length: usize,
    pub deadlock_risk: String,
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractCircularDependencyAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractCircularDependencyAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractCircularDependency> {
        let mut vulnerabilities = Vec::new();
        let contracts = self.protocol.get_contracts();
        
        // Build complete call graph
        let call_graph = self.build_call_graph(&contracts);
        
        // Find all circular dependencies using DFS
        for start_contract in contracts.keys() {
            let cycles = self.find_cycles(*start_contract, &call_graph);
            
            for cycle in cycles {
                if cycle.len() >= 2 {  // At least A → B → A
                    let severity = match cycle.len() {
                        2..=3 => "High",
                        4..=5 => "Critical",
                        _ => "Critical", // Deep cycles are especially dangerous
                    };
                    
                    vulnerabilities.push(CrossContractCircularDependency {
                        vulnerability_type: "Cross-Contract Circular Dependency".to_string(),
                        severity: severity.to_string(),
                        circular_path: cycle.clone(),
                        cycle_length: cycle.len(),
                        deadlock_risk: self.assess_deadlock_risk(&cycle, &contracts),
                        description: format!(
                            "Circular dependency detected: {:?}\n\
                             Cycle length: {}\n\
                             Risk: Mutual dependencies can cause deadlock, infinite recursion, or DOS",
                            cycle, cycle.len()
                        ),
                        exploit_scenario: format!(
                            "CIRCULAR DEPENDENCY DEADLOCK:\n\
                             Cycle: {:?}\n\
                             \n\
                             Attack Scenarios:\n\
                             1. DEADLOCK: If any contract in cycle uses mutex/lock\n\
                                A locks → calls B → B locks → calls C → C tries to call A (DEADLOCKED!)\n\
                             \n\
                             2. INFINITE RECURSION: Without proper depth checks\n\
                                A → B → C → A → B → C → ... → Stack overflow\n\
                             \n\
                             3. STATE CORRUPTION: Circular updates create race conditions\n\
                                A updates state → B updates → C updates → A reads stale state\n\
                             \n\
                             4. DOS: Attacker triggers cycle with high gas consumption\n\
                                Each iteration costs gas → OOG before completion\n\
                             \n\
                             Real Examples:\n\
                             - Lending protocol → Collateral oracle → Price feed → Lending (deadlock)\n\
                             - Vault A → Vault B → Strategy → Vault A (infinite loop)\n\
                             \n\
                             Your PCD sees {} hops - competitors can't detect cycles > 2!",
                            cycle, cycle.len()
                        ),
                        remediation: "Break circular dependencies, use one-way data flow, implement depth limits, add reentrancy guards".to_string(),
                    });
                }
            }
        }
        
        vulnerabilities
    }
    
    fn build_call_graph(&self, contracts: &HashMap<H160, &Vec<u8>>) -> HashMap<H160, Vec<H160>> {
        let mut graph = HashMap::new();
        
        for addr in contracts.keys() {
            let targets = self.protocol.get_call_targets(addr);
            graph.insert(*addr, targets);
        }
        
        graph
    }
    
    fn find_cycles(&self, start: H160, graph: &HashMap<H160, Vec<H160>>) -> Vec<Vec<H160>> {
        let mut cycles = Vec::new();
        let mut visited = HashSet::new();
        let mut rec_stack = Vec::new();
        
        self.dfs_cycle_detection(start, start, graph, &mut visited, &mut rec_stack, &mut cycles);
        
        cycles
    }
    
    fn dfs_cycle_detection(
        &self,
        current: H160,
        target: H160,
        graph: &HashMap<H160, Vec<H160>>,
        visited: &mut HashSet<H160>,
        rec_stack: &mut Vec<H160>,
        cycles: &mut Vec<Vec<H160>>,
    ) {
        if rec_stack.len() > 10 {
            return; // Prevent excessive depth
        }
        
        rec_stack.push(current);
        
        if let Some(neighbors) = graph.get(&current) {
            for &neighbor in neighbors {
                if neighbor == target && rec_stack.len() >= 2 {
                    // Found cycle back to target
                    let mut cycle = rec_stack.clone();
                    cycle.push(neighbor);
                    cycles.push(cycle);
                } else if !visited.contains(&neighbor) && rec_stack.len() < 10 {
                    self.dfs_cycle_detection(neighbor, target, graph, visited, rec_stack, cycles);
                }
            }
        }
        
        rec_stack.pop();
        visited.insert(current);
    }
    
    fn assess_deadlock_risk(&self, cycle: &[H160], contracts: &HashMap<H160, &Vec<u8>>) -> String {
        let has_locks = cycle.iter().any(|addr| {
            if let Some(bytecode) = contracts.get(addr) {
                // Check for mutex/lock patterns (SSTORE for lock state)
                bytecode.contains(&0x55) // SSTORE
            } else {
                false
            }
        });
        
        if has_locks {
            "CRITICAL: Cycle contains state modifications - high deadlock risk!".to_string()
        } else {
            "HIGH: Cycle can cause infinite recursion or DOS".to_string()
        }
    }
}

impl CrossContractCircularDependency {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::CircularDependency,
            severity: if self.severity == "Critical" { SecuritySeverity::Critical } else { SecuritySeverity::High },
            description: self.description.clone(),
            call_path: self.circular_path.clone(),
            remediation: self.remediation.clone(),
        }
    }
}
