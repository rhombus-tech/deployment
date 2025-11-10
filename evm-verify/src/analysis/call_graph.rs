use ethers::types::H160;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet, VecDeque};
use anyhow::Result;
use crate::analysis::tarjan_scc::TarjanSCC;

/// Advanced call graph for cross-contract analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraph {
    /// Contract nodes in the graph
    pub nodes: HashMap<H160, ContractNode>,
    /// Call edges between contracts
    pub edges: Vec<CallEdge>,
    /// Adjacency list for efficient traversal
    adjacency: HashMap<H160, Vec<H160>>,
    /// Reverse adjacency list (who calls this contract)
    reverse_adjacency: HashMap<H160, Vec<H160>>,
}

/// Information about a contract node in the call graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractNode {
    pub address: H160,
    pub contract_type: ContractType,
    pub call_count_outgoing: u32,
    pub call_count_incoming: u32,
    pub is_entry_point: bool,
    pub critical_level: CriticalityLevel,
}

/// Type of contract based on behavior analysis
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractType {
    Router,
    Pool,
    Token,
    Vault,
    Governance,
    Oracle,
    Bridge,
    Unknown,
}

/// How critical is this contract to the protocol
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CriticalityLevel {
    Critical,  // Core protocol logic
    High,      // Important but not critical
    Medium,    // Peripheral functionality
    Low,       // Helper contracts
}

/// Represents a call from one contract to another
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    pub from: H160,
    pub to: H160,
    pub call_type: CallType,
    pub call_count: u32,
    pub value_transferred: bool,
    pub is_reentrant: bool,
}

/// Type of inter-contract call
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallType {
    Call,
    DelegateCall,
    StaticCall,
    CallCode,
}

impl CallType {
    pub fn from_opcode(opcode: u8) -> Self {
        match opcode {
            0xF1 => CallType::Call,
            0xF2 => CallType::CallCode,
            0xF4 => CallType::DelegateCall,
            0xFA => CallType::StaticCall,
            _ => CallType::Call,
        }
    }
}

/// Attack path through the protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPath {
    pub path: Vec<H160>,
    pub vulnerability_type: AttackPathType,
    pub severity: AttackSeverity,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackPathType {
    ReentrancyChain,
    CircularDependency,
    PrivilegeEscalation,
    ValueLeakage,
    StateManipulation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl CallGraph {
    /// Create a new empty call graph
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            adjacency: HashMap::new(),
            reverse_adjacency: HashMap::new(),
        }
    }

    /// Add a contract node to the graph
    pub fn add_node(&mut self, address: H160, contract_type: ContractType) {
        if !self.nodes.contains_key(&address) {
            self.nodes.insert(address, ContractNode {
                address,
                contract_type,
                call_count_outgoing: 0,
                call_count_incoming: 0,
                is_entry_point: false,
                critical_level: CriticalityLevel::Medium,
            });
            self.adjacency.insert(address, Vec::new());
            self.reverse_adjacency.insert(address, Vec::new());
        }
    }

    /// Add a call edge between two contracts
    pub fn add_call(
        &mut self,
        from: H160,
        to: H160,
        call_type: CallType,
        value_transferred: bool,
    ) {
        // Ensure both nodes exist
        self.add_node(from, ContractType::Unknown);
        self.add_node(to, ContractType::Unknown);

        // Update call counts
        if let Some(from_node) = self.nodes.get_mut(&from) {
            from_node.call_count_outgoing += 1;
        }
        if let Some(to_node) = self.nodes.get_mut(&to) {
            to_node.call_count_incoming += 1;
        }

        // Check if edge already exists
        let edge_exists = self.edges.iter_mut().find(|e| e.from == from && e.to == to);
        
        if let Some(edge) = edge_exists {
            edge.call_count += 1;
        } else {
            // Add new edge
            self.edges.push(CallEdge {
                from,
                to,
                call_type,
                call_count: 1,
                value_transferred,
                is_reentrant: false,
            });

            // Update adjacency lists
            self.adjacency.entry(from).or_insert_with(Vec::new).push(to);
            self.reverse_adjacency.entry(to).or_insert_with(Vec::new).push(from);
        }
    }

    /// Find all cycles in the call graph using Tarjan's SCC algorithm
    /// This is O(V + E) instead of O(V * (V + E)) for naive DFS
    pub fn find_cycles(&self) -> Vec<Vec<H160>> {
        let mut tarjan = TarjanSCC::new();
        tarjan.find_sccs(&self.adjacency)
    }
    
    /// Legacy DFS-based cycle detection (kept for comparison/fallback)
    #[allow(dead_code)]
    fn find_cycles_dfs(&self) -> Vec<Vec<H160>> {
        let mut cycles = Vec::new();
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        let mut path = Vec::new();

        for node_addr in self.nodes.keys() {
            if !visited.contains(node_addr) {
                self.dfs_cycles(*node_addr, &mut visited, &mut rec_stack, &mut path, &mut cycles);
            }
        }

        cycles
    }

    fn dfs_cycles(
        &self,
        node: H160,
        visited: &mut HashSet<H160>,
        rec_stack: &mut HashSet<H160>,
        path: &mut Vec<H160>,
        cycles: &mut Vec<Vec<H160>>,
    ) {
        visited.insert(node);
        rec_stack.insert(node);
        path.push(node);

        if let Some(neighbors) = self.adjacency.get(&node) {
            for &neighbor in neighbors {
                if !visited.contains(&neighbor) {
                    self.dfs_cycles(neighbor, visited, rec_stack, path, cycles);
                } else if rec_stack.contains(&neighbor) {
                    // Found a cycle
                    if let Some(cycle_start) = path.iter().position(|&p| p == neighbor) {
                        let cycle = path[cycle_start..].to_vec();
                        cycles.push(cycle);
                    }
                }
            }
        }

        path.pop();
        rec_stack.remove(&node);
    }

    /// Detect reentrancy attack paths
    pub fn find_reentrancy_paths(&self) -> Vec<AttackPath> {
        let mut attack_paths = Vec::new();

        // Find all paths where contract A calls B, and B can call back to A
        for edge in &self.edges {
            // Check if there's a path back from 'to' to 'from'
            if self.has_path(edge.to, edge.from) {
                let path = self.find_path(edge.from, edge.to, edge.from);
                if path.len() > 1 {
                    let severity = match edge.call_type {
                        CallType::DelegateCall => AttackSeverity::Critical,
                        CallType::Call if edge.value_transferred => AttackSeverity::High,
                        _ => AttackSeverity::Medium,
                    };

                    attack_paths.push(AttackPath {
                        path,
                        vulnerability_type: AttackPathType::ReentrancyChain,
                        severity,
                        description: format!(
                            "Potential reentrancy: {:?} → {:?} with callback path",
                            edge.from, edge.to
                        ),
                    });
                }
            }
        }

        attack_paths
    }

    /// Check if there's a path from source to target
    fn has_path(&self, source: H160, target: H160) -> bool {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(source);
        visited.insert(source);

        while let Some(current) = queue.pop_front() {
            if current == target {
                return true;
            }

            if let Some(neighbors) = self.adjacency.get(&current) {
                for &neighbor in neighbors {
                    if !visited.contains(&neighbor) {
                        visited.insert(neighbor);
                        queue.push_back(neighbor);
                    }
                }
            }
        }

        false
    }

    /// Find a path from source through intermediate to target using BFS
    /// Returns the actual path if found, reconstructed using parent tracking
    fn find_path(&self, source: H160, intermediate: H160, target: H160) -> Vec<H160> {
        // First, find path from source to intermediate
        let path1 = self.bfs_path(source, intermediate);
        if path1.is_empty() {
            return vec![source]; // No path found
        }
        
        // Then find path from intermediate to target
        let path2 = self.bfs_path(intermediate, target);
        if path2.is_empty() {
            return path1; // Only partial path
        }
        
        // Combine paths (remove duplicate intermediate node)
        let mut full_path = path1;
        full_path.extend_from_slice(&path2[1..]);
        full_path
    }
    
    /// BFS pathfinding with parent tracking for path reconstruction
    fn bfs_path(&self, start: H160, goal: H160) -> Vec<H160> {
        if start == goal {
            return vec![start];
        }
        
        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();
        let mut parent: HashMap<H160, H160> = HashMap::new();
        
        queue.push_back(start);
        visited.insert(start);
        
        while let Some(current) = queue.pop_front() {
            if current == goal {
                // Reconstruct path
                let mut path = vec![goal];
                let mut node = goal;
                while let Some(&prev) = parent.get(&node) {
                    path.push(prev);
                    node = prev;
                    if node == start {
                        break;
                    }
                }
                path.reverse();
                return path;
            }
            
            if let Some(neighbors) = self.adjacency.get(&current) {
                for &neighbor in neighbors {
                    if !visited.contains(&neighbor) {
                        visited.insert(neighbor);
                        parent.insert(neighbor, current);
                        queue.push_back(neighbor);
                    }
                }
            }
        }
        
        Vec::new() // No path found
    }

    /// Find privilege escalation paths
    pub fn find_privilege_escalation_paths(&self) -> Vec<AttackPath> {
        let mut attack_paths = Vec::new();

        // Look for DELEGATECALL chains that could escalate privileges
        for edge in &self.edges {
            if edge.call_type == CallType::DelegateCall {
                // DELEGATECALL is dangerous - calling contract's context is preserved
                attack_paths.push(AttackPath {
                    path: vec![edge.from, edge.to],
                    vulnerability_type: AttackPathType::PrivilegeEscalation,
                    severity: AttackSeverity::Critical,
                    description: format!(
                        "DELEGATECALL from {:?} to {:?} allows privilege escalation",
                        edge.from, edge.to
                    ),
                });
            }
        }

        attack_paths
    }

    /// Identify critical contracts (most connected)
    pub fn identify_critical_contracts(&mut self) {
        let total_nodes = self.nodes.len() as f32;
        
        for node in self.nodes.values_mut() {
            let total_calls = node.call_count_incoming + node.call_count_outgoing;
            let connection_ratio = total_calls as f32 / total_nodes;

            node.critical_level = if connection_ratio > 0.5 {
                CriticalityLevel::Critical
            } else if connection_ratio > 0.25 {
                CriticalityLevel::High
            } else if connection_ratio > 0.1 {
                CriticalityLevel::Medium
            } else {
                CriticalityLevel::Low
            };
        }
    }

    /// Identify entry point contracts (no incoming calls or only from EOAs)
    pub fn identify_entry_points(&mut self) {
        for (address, node_data) in &mut self.nodes {
            if let Some(incoming) = self.reverse_adjacency.get(address) {
                node_data.is_entry_point = incoming.is_empty();
            } else {
                node_data.is_entry_point = true;
            }
        }
    }

    /// Get all attack paths (comprehensive analysis)
    pub fn find_all_attack_paths(&self) -> Vec<AttackPath> {
        let mut all_paths = Vec::new();

        // Reentrancy paths
        all_paths.extend(self.find_reentrancy_paths());

        // Privilege escalation paths
        all_paths.extend(self.find_privilege_escalation_paths());

        // Circular dependency paths
        for cycle in self.find_cycles() {
            all_paths.push(AttackPath {
                path: cycle.clone(),
                vulnerability_type: AttackPathType::CircularDependency,
                severity: AttackSeverity::High,
                description: format!("Circular dependency detected: {} contracts", cycle.len()),
            });
        }

        all_paths
    }

    /// Get graph statistics
    pub fn get_statistics(&self) -> CallGraphStatistics {
        let total_calls: u32 = self.edges.iter().map(|e| e.call_count).sum();
        let delegate_calls = self.edges.iter().filter(|e| e.call_type == CallType::DelegateCall).count();
        let value_transfers = self.edges.iter().filter(|e| e.value_transferred).count();

        CallGraphStatistics {
            total_contracts: self.nodes.len(),
            total_call_edges: self.edges.len(),
            total_calls,
            delegate_call_count: delegate_calls,
            value_transfer_count: value_transfers,
            average_calls_per_contract: if self.nodes.is_empty() {
                0.0
            } else {
                total_calls as f32 / self.nodes.len() as f32
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraphStatistics {
    pub total_contracts: usize,
    pub total_call_edges: usize,
    pub total_calls: u32,
    pub delegate_call_count: usize,
    pub value_transfer_count: usize,
    pub average_calls_per_contract: f32,
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}
