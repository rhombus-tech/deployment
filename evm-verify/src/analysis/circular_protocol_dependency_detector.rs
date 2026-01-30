use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Circular Protocol Dependency Detection
/// 
/// Detects circular dependencies that can cause deadlocks:
/// 1. Protocol A depends on Protocol B which depends on Protocol A
/// 2. Circular oracle dependencies
/// 3. Mutual liquidity dependencies
/// 4. Deadlock in pause/unpause mechanisms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CircularProtocolDependencyVulnerability {
    /// Critical: Circular dependency deadlock
    CircularDependencyDeadlock {
        description: String,
        protocol_a: String,
        protocol_b: String,
        dependency_type: String,
        confidence: f32,
    },
    /// High: Circular oracle reference
    CircularOracleReference {
        description: String,
        location: usize,
        oracle_chain: Vec<String>,
    },
    /// High: Mutual liquidity dependency
    MutualLiquidityDependency {
        description: String,
        location: usize,
    },
    /// Medium: Circular pause mechanism
    CircularPauseMechanism {
        description: String,
        location: usize,
    },
}

pub struct CircularProtocolDependencyDetector {
    bytecode: Vec<u8>,
}

impl CircularProtocolDependencyDetector {
    pub fn new(bytecode: Vec<u8>) -> Self {
        Self { bytecode }
    }

    pub fn detect_vulnerabilities(&self) -> Vec<CircularProtocolDependencyVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Build dependency graph
        let external_calls = self.identify_external_protocol_calls();
        let dependency_graph = self.build_dependency_graph(&external_calls);
        
        // Pattern 1: Detect circular dependencies in call graph
        let cycles = self.find_cycles_in_dependency_graph(&dependency_graph);
        
        for cycle in cycles {
            if cycle.len() >= 2 {
                let dependency_type = self.classify_dependency_type(&cycle, &external_calls);
                
                vulnerabilities.push(CircularProtocolDependencyVulnerability::CircularDependencyDeadlock {
                    description: format!(
                        "Circular dependency detected: {} protocols form a dependency cycle",
                        cycle.len()
                    ),
                    protocol_a: cycle[0].clone(),
                    protocol_b: cycle[1].clone(),
                    dependency_type,
                    confidence: 0.80,
                });
            }
        }
        
        // Pattern 2: Circular oracle references
        for i in 0..self.bytecode.len().saturating_sub(200) {
            if self.is_oracle_aggregation(i) {
                let oracle_chain = self.trace_oracle_chain(i, 5);
                
                if self.has_circular_reference(&oracle_chain) {
                    vulnerabilities.push(CircularProtocolDependencyVulnerability::CircularOracleReference {
                        description: "Oracle price depends on another oracle that references back".to_string(),
                        location: i,
                        oracle_chain,
                    });
                }
            }
        }
        
        // Pattern 3: Mutual liquidity dependencies
        for i in 0..self.bytecode.len().saturating_sub(150) {
            if self.is_liquidity_check(i) {
                let depends_on_external = self.checks_external_liquidity(i, i + 150);
                let provides_to_same = self.provides_liquidity_to_same(i, i + 150, &external_calls);
                
                if depends_on_external && provides_to_same {
                    vulnerabilities.push(CircularProtocolDependencyVulnerability::MutualLiquidityDependency {
                        description: "Protocol checks liquidity from same protocol it provides to".to_string(),
                        location: i,
                    });
                }
            }
        }
        
        // Pattern 4: Circular pause mechanisms
        for i in 0..self.bytecode.len().saturating_sub(100) {
            if self.is_pause_check(i) {
                let checks_external_pause = self.checks_external_pause_state(i, i + 100);
                
                if checks_external_pause {
                    let can_cause_deadlock = self.pause_can_cause_deadlock(i, i + 100);
                    
                    if can_cause_deadlock {
                        vulnerabilities.push(CircularProtocolDependencyVulnerability::CircularPauseMechanism {
                            description: "Pause state depends on external protocol that may check back".to_string(),
                            location: i,
                        });
                    }
                }
            }
        }
        
        vulnerabilities
    }
    
    fn identify_external_protocol_calls(&self) -> Vec<ExternalCall> {
        let mut calls = Vec::new();
        
        for i in 0..self.bytecode.len().saturating_sub(50) {
            if self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xfa { // CALL or STATICCALL
                // Extract target address if it's a PUSH20
                if let Some(address) = self.get_call_target(i) {
                    let function_sig = self.get_function_signature(i);
                    
                    calls.push(ExternalCall {
                        location: i,
                        target_address: address,
                        function_signature: function_sig,
                    });
                }
            }
        }
        
        calls
    }
    
    fn get_call_target(&self, call_location: usize) -> Option<String> {
        // Look backwards for PUSH20 (address)
        for i in (call_location.saturating_sub(30)..call_location).rev() {
            if self.bytecode[i] == 0x73 && i + 20 < self.bytecode.len() { // PUSH20
                let addr = &self.bytecode[i + 1..i + 21];
                return Some(format!("0x{}", hex::encode(addr)));
            }
        }
        None
    }
    
    fn get_function_signature(&self, call_location: usize) -> String {
        // Look backwards for PUSH4 (function selector)
        for i in (call_location.saturating_sub(20)..call_location).rev() {
            if self.bytecode[i] == 0x63 && i + 4 < self.bytecode.len() { // PUSH4
                let sig = &self.bytecode[i + 1..i + 5];
                return format!("0x{}", hex::encode(sig));
            }
        }
        "unknown".to_string()
    }
    
    fn build_dependency_graph(&self, calls: &[ExternalCall]) -> HashMap<String, HashSet<String>> {
        let mut graph = HashMap::new();
        
        // Group calls by target to build dependency relationships
        for call in calls {
            graph.entry("this_contract".to_string())
                .or_insert_with(HashSet::new)
                .insert(call.target_address.clone());
        }
        
        graph
    }
    
    fn find_cycles_in_dependency_graph(&self, graph: &HashMap<String, HashSet<String>>) -> Vec<Vec<String>> {
        let mut cycles = Vec::new();
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        
        for node in graph.keys() {
            if !visited.contains(node) {
                self.dfs_find_cycles(node, graph, &mut visited, &mut rec_stack, &mut Vec::new(), &mut cycles);
            }
        }
        
        cycles
    }
    
    fn dfs_find_cycles(
        &self,
        node: &str,
        graph: &HashMap<String, HashSet<String>>,
        visited: &mut HashSet<String>,
        rec_stack: &mut HashSet<String>,
        path: &mut Vec<String>,
        cycles: &mut Vec<Vec<String>>,
    ) {
        visited.insert(node.to_string());
        rec_stack.insert(node.to_string());
        path.push(node.to_string());
        
        if let Some(neighbors) = graph.get(node) {
            for neighbor in neighbors {
                if !visited.contains(neighbor) {
                    self.dfs_find_cycles(neighbor, graph, visited, rec_stack, path, cycles);
                } else if rec_stack.contains(neighbor) {
                    // Found a cycle
                    if let Some(start_idx) = path.iter().position(|n| n == neighbor) {
                        cycles.push(path[start_idx..].to_vec());
                    }
                }
            }
        }
        
        path.pop();
        rec_stack.remove(node);
    }
    
    fn classify_dependency_type(&self, _cycle: &[String], calls: &[ExternalCall]) -> String {
        // Classify what type of dependency creates the cycle
        
        let has_oracle_call = calls.iter().any(|c| {
            c.function_signature.starts_with("0xfe") || // latestRoundData
            c.function_signature.starts_with("0x50")    // latestAnswer
        });
        
        if has_oracle_call {
            return "oracle_dependency".to_string();
        }
        
        let has_liquidity_call = calls.iter().any(|c| {
            c.function_signature.starts_with("0x02") || // getReserves
            c.function_signature.starts_with("0x0902")  // balanceOf
        });
        
        if has_liquidity_call {
            return "liquidity_dependency".to_string();
        }
        
        "unknown_dependency".to_string()
    }
    
    fn is_oracle_aggregation(&self, location: usize) -> bool {
        if location + 50 > self.bytecode.len() {
            return false;
        }
        
        // Multiple oracle calls + aggregation logic
        let oracle_call_count = self.bytecode[location..location + 50]
            .windows(4)
            .filter(|w| w[0] == 0x63 && (w[1] == 0xfe || w[1] == 0x50))
            .count();
        
        oracle_call_count >= 2
    }
    
    fn trace_oracle_chain(&self, start: usize, max_depth: usize) -> Vec<String> {
        let mut chain = Vec::new();
        let mut current = start;
        
        for _ in 0..max_depth {
            if let Some(address) = self.get_call_target(current) {
                if chain.contains(&address) {
                    break; // Circular reference found
                }
                chain.push(address);
                
                // Find next oracle call
                if let Some(next) = self.find_next_oracle_call(current + 1, current + 100) {
                    current = next;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        
        chain
    }
    
    fn find_next_oracle_call(&self, start: usize, end: usize) -> Option<usize> {
        let range_end = end.min(self.bytecode.len());
        
        for i in start..range_end {
            if (self.bytecode[i] == 0xf1 || self.bytecode[i] == 0xfa) &&
               self.get_function_signature(i).starts_with("0xfe") {
                return Some(i);
            }
        }
        
        None
    }
    
    fn has_circular_reference(&self, chain: &[String]) -> bool {
        let mut seen = HashSet::new();
        
        for addr in chain {
            if !seen.insert(addr.clone()) {
                return true; // Duplicate found = circular
            }
        }
        
        false
    }
    
    fn is_liquidity_check(&self, location: usize) -> bool {
        if location + 30 > self.bytecode.len() {
            return false;
        }
        
        // getReserves() or similar liquidity checks
        self.bytecode[location..location + 30].windows(4).any(|w| {
            w[0] == 0x63 && (w[1] == 0x09 || w[1] == 0x02) // getReserves patterns
        })
    }
    
    fn checks_external_liquidity(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        
        self.bytecode[start..range_end]
            .iter()
            .any(|&b| b == 0xf1 || b == 0xfa) // External call
    }
    
    fn provides_liquidity_to_same(&self, start: usize, end: usize, calls: &[ExternalCall]) -> bool {
        // Check if contract provides liquidity to the same protocol it checks
        let range_end = end.min(self.bytecode.len());
        
        // Look for addLiquidity or similar in same range
        self.bytecode[start..range_end]
            .windows(4)
            .any(|w| w[0] == 0x63 && w[1] == 0xe8) && // addLiquidity pattern
        !calls.is_empty()
    }
    
    fn is_pause_check(&self, location: usize) -> bool {
        if location + 20 > self.bytecode.len() {
            return false;
        }
        
        // paused() check
        self.bytecode[location..location + 20].windows(4).any(|w| {
            w[0] == 0x63 && w[1] == 0x5c && w[2] == 0x97 // paused() selector
        })
    }
    
    fn checks_external_pause_state(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // External STATICCALL to check pause state
        self.bytecode[start..range_end]
            .windows(5)
            .any(|w| {
                w[0] == 0xfa && // STATICCALL
                w.iter().any(|&b| b == 0x63) // Function selector
            })
    }
    
    fn pause_can_cause_deadlock(&self, start: usize, end: usize) -> bool {
        let range_end = end.min(self.bytecode.len());
        if start >= range_end {
            return false;
        }
        
        // If external pause check fails, does it prevent this contract from unpausing?
        self.bytecode[start..range_end]
            .windows(2)
            .any(|w| w[0] == 0x15 && w[1] == 0xfd) // ISZERO + REVERT
    }
}

#[derive(Debug, Clone)]
struct ExternalCall {
    location: usize,
    target_address: String,
    function_signature: String,
}
