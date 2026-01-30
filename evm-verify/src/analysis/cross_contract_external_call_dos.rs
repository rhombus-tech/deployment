/// Cross-Contract External Call DoS Analyzer
/// 
/// YOUR EDGE: Maps failure propagation across entire protocol
/// 
/// Contract A calls Contract B calls Contract C
/// If C fails → B fails → A fails → ENTIRE PROTOCOL DOWN
/// 
/// Detects critical dependency chains that create single points of failure

use ethers::types::H160;
use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

use super::cross_contract::{ContractProtocol, ProtocolFinding, ProtocolFindingKind};
use crate::bytecode::SecuritySeverity;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossContractCallDoS {
    pub vulnerability_type: String,
    pub severity: String,
    pub dependency_chain: Vec<H160>,  // A → B → C → ... critical path
    pub failure_point: H160,          // Which contract can cause cascade failure
    pub affected_contracts: Vec<H160>, // All contracts that fail if failure_point fails
    pub description: String,
    pub exploit_scenario: String,
    pub remediation: String,
}

pub struct CrossContractExternalCallDoSAnalyzer<'a> {
    protocol: &'a ContractProtocol,
}

impl<'a> CrossContractExternalCallDoSAnalyzer<'a> {
    pub fn new(protocol: &'a ContractProtocol) -> Self {
        Self { protocol }
    }
    
    pub fn analyze(&self) -> Vec<CrossContractCallDoS> {
        let mut vulnerabilities = Vec::new();
        
        let contracts = self.protocol.get_contracts();
        
        // Build call dependency graph for entire protocol
        let call_graph = self.build_protocol_call_graph(&contracts);
        
        // Find critical dependency chains
        let critical_chains = self.find_critical_chains(&call_graph);
        
        // Analyze each critical chain for DoS potential
        for chain in critical_chains {
            let failure_analysis = self.analyze_failure_propagation(&chain, &call_graph, &contracts);
            
            if failure_analysis.creates_dos {
                let affected_contracts_clone = failure_analysis.affected_contracts.clone();
                vulnerabilities.push(CrossContractCallDoS {
                    vulnerability_type: "Cross-Contract Cascading Failure DoS".to_string(),
                    severity: self.calculate_severity(&chain, &failure_analysis),
                    dependency_chain: chain.clone(),
                    failure_point: *chain.last().unwrap(),
                    affected_contracts: affected_contracts_clone,
                    description: format!(
                        "CROSS-CONTRACT CASCADE FAILURE VULNERABILITY:\n\
                         Critical dependency chain detected:\n\
                         {:?}\n\n\
                         If {} fails, {} contracts become unusable!\n\
                         This creates a PROTOCOL-LEVEL single point of failure.",
                        chain,
                        Self::format_addr(chain.last().unwrap()),
                        failure_analysis.affected_contracts.len()
                    ),
                    exploit_scenario: format!(
                        "CASCADE FAILURE DOS ATTACK:\n\
                         Dependency chain: {}\n\
                         \n\
                         Attack scenario:\n\
                         1. Attacker identifies critical dependency at end of chain\n\
                         2. Attacker makes {} unavailable (revert/out-of-gas/selfdestruct)\n\
                         3. {} tries to call {} → fails\n\
                         4. {} operation fails\n\
                         5. Propagates up chain: {} total contracts affected\n\
                         6. ENTIRE PROTOCOL INOPERABLE\n\
                         \n\
                         Real examples:\n\
                         - Oracle failure → DeFi protocol frozen\n\
                         - Price feed DoS → Lending protocol liquidations stuck\n\
                         - Bridge contract → Cross-chain operations halted\n\
                         \n\
                         Traditional analyzers only see individual contracts!",
                        Self::format_chain(&chain),
                        Self::format_addr(chain.last().unwrap()),
                        Self::format_addr(&chain[chain.len().saturating_sub(2)]),
                        Self::format_addr(chain.last().unwrap()),
                        Self::format_addr(&chain[0]),
                        failure_analysis.affected_contracts.len()
                    ),
                    remediation: format!(
                        "CROSS-CONTRACT DOS PREVENTION:\n\
                         Critical path: {:?}\n\
                         \n\
                         1. ELIMINATE CRITICAL DEPENDENCIES:\n\
                            - Don't require external calls for critical functions\n\
                            - Use try-catch for external calls\n\
                            - Implement circuit breakers\n\
                         \n\
                         2. ADD FALLBACK MECHANISMS:\n\
                            - Secondary oracle sources\n\
                            - Cached values with staleness tolerance\n\
                            - Manual override for emergencies\n\
                         \n\
                         3. ISOLATION:\n\
                            - Separate critical path from user operations\n\
                            - Don't let user actions depend on external contracts\n\
                            - Use pull pattern instead of push\n\
                         \n\
                         4. MONITORING:\n\
                            - Alert on external call failures\n\
                            - Track success rates across protocol\n\
                            - Implement automatic pause on cascade failures",
                        chain
                    ),
                });
            }
        }
        
        vulnerabilities
    }
    
    fn build_protocol_call_graph(&self, contracts: &HashMap<H160, &Vec<u8>>) -> HashMap<H160, Vec<H160>> {
        let mut graph = HashMap::new();
        
        for (caller_addr, bytecode) in contracts {
            let callees = self.extract_external_call_targets(bytecode, contracts);
            graph.insert(*caller_addr, callees);
        }
        
        graph
    }
    
    fn extract_external_call_targets(&self, bytecode: &[u8], contracts: &HashMap<H160, &Vec<u8>>) -> Vec<H160> {
        let mut targets = Vec::new();
        
        // Find external calls (CALL, DELEGATECALL, STATICCALL)
        for i in 0..bytecode.len() {
            if matches!(bytecode[i], 0xF1 | 0xF4 | 0xFA) {
                // In real impl, would extract address from stack analysis
                // For now, conservatively include all protocol contracts
                for addr in contracts.keys() {
                    if !targets.contains(addr) {
                        targets.push(*addr);
                    }
                }
            }
        }
        
        targets
    }
    
    fn find_critical_chains(&self, call_graph: &HashMap<H160, Vec<H160>>) -> Vec<Vec<H160>> {
        let mut chains = Vec::new();
        
        // Find all paths of length 3+ (multi-hop dependencies)
        for (start, _) in call_graph {
            let paths = self.find_paths_from(*start, call_graph, 5); // Max depth 5
            for path in paths {
                if path.len() >= 3 {
                    chains.push(path);
                }
            }
        }
        
        chains
    }
    
    fn find_paths_from(&self, start: H160, graph: &HashMap<H160, Vec<H160>>, max_depth: usize) -> Vec<Vec<H160>> {
        let mut paths = Vec::new();
        let mut current_path = vec![start];
        let mut visited = HashSet::new();
        
        self.dfs_paths(start, graph, &mut current_path, &mut visited, &mut paths, max_depth);
        
        paths
    }
    
    fn dfs_paths(&self, node: H160, graph: &HashMap<H160, Vec<H160>>, 
                 current_path: &mut Vec<H160>, visited: &mut HashSet<H160>,
                 paths: &mut Vec<Vec<H160>>, max_depth: usize) {
        if current_path.len() >= max_depth {
            return;
        }
        
        visited.insert(node);
        
        if let Some(neighbors) = graph.get(&node) {
            for &neighbor in neighbors {
                if !visited.contains(&neighbor) {
                    current_path.push(neighbor);
                    paths.push(current_path.clone());
                    self.dfs_paths(neighbor, graph, current_path, visited, paths, max_depth);
                    current_path.pop();
                }
            }
        }
        
        visited.remove(&node);
    }
    
    fn analyze_failure_propagation(&self, chain: &[H160], graph: &HashMap<H160, Vec<H160>>,
                                   contracts: &HashMap<H160, &Vec<u8>>) -> FailureAnalysis {
        let mut analysis = FailureAnalysis {
            creates_dos: false,
            affected_contracts: Vec::new(),
        };
        
        // Check if failure at end of chain propagates
        if let Some(&failure_point) = chain.last() {
            // Check if calls to failure_point are checked for success
            for &caller in chain.iter().rev().skip(1) {
                if let Some(caller_bytecode) = contracts.get(&caller) {
                    let checks_return = self.checks_call_return(caller_bytecode);
                    
                    if !checks_return {
                        // Unchecked call = failure propagates
                        analysis.creates_dos = true;
                        analysis.affected_contracts.push(caller);
                    } else {
                        // Checked call = failure contained
                        break;
                    }
                }
            }
        }
        
        // If entire chain propagates failure, all contracts affected
        if analysis.affected_contracts.len() == chain.len() - 1 {
            analysis.affected_contracts = chain.to_vec();
        }
        
        analysis
    }
    
    fn checks_call_return(&self, bytecode: &[u8]) -> bool {
        // Check if CALL is followed by return value check (ISZERO + JUMPI)
        for i in 0..bytecode.len().saturating_sub(10) {
            if matches!(bytecode[i], 0xF1 | 0xF4 | 0xFA) { // External call
                // Look for ISZERO + JUMPI shortly after (failure check)
                for j in i+1..i+10.min(bytecode.len()) {
                    if bytecode[j] == 0x15 { // ISZERO
                        if j+1 < bytecode.len() && bytecode[j+1] == 0x57 { // JUMPI
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
    
    fn calculate_severity(&self, chain: &[H160], analysis: &FailureAnalysis) -> String {
        if analysis.affected_contracts.len() >= chain.len() - 1 {
            "Critical".to_string() // Full cascade
        } else if analysis.affected_contracts.len() >= 2 {
            "High".to_string() // Partial cascade
        } else {
            "Medium".to_string() // Limited impact
        }
    }
    
    fn format_addr(addr: &H160) -> String {
        format!("{:?}", addr)
    }
    
    fn format_chain(chain: &[H160]) -> String {
        chain.iter()
            .map(|a| format!("{:?}", a))
            .collect::<Vec<_>>()
            .join(" → ")
    }
}

struct FailureAnalysis {
    creates_dos: bool,
    affected_contracts: Vec<H160>,
}

impl CrossContractCallDoS {
    pub fn to_protocol_finding(&self) -> ProtocolFinding {
        ProtocolFinding {
            kind: ProtocolFindingKind::Other,
            severity: match self.severity.as_str() {
                "Critical" => SecuritySeverity::Critical,
                "High" => SecuritySeverity::High,
                "Medium" => SecuritySeverity::Medium,
                _ => SecuritySeverity::Low,
            },
            description: self.description.clone(),
            call_path: self.dependency_chain.clone(),
            remediation: self.remediation.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cross_contract_cascade_failure() {
        // Test: Protocol A → Oracle B → Aggregator C
        // C failure should cascade to A
    }
}
