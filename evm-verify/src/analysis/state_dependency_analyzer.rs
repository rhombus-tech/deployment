use ethers::types::{H160, U256};
use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};

/// Analyzes state dependencies between contracts
#[derive(Debug, Clone)]
pub struct StateDependencyAnalyzer {
    /// Dependencies between contracts
    dependencies: Vec<StateDependency>,
    /// Storage slots accessed by each contract
    storage_access: HashMap<H160, HashSet<StorageAccess>>,
    /// Shared state between contracts
    shared_state: Vec<SharedState>,
}

/// A dependency where one contract's state affects another
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDependency {
    pub dependent_contract: H160,
    pub dependency_contract: H160,
    pub dependency_type: DependencyType,
    pub storage_slots: Vec<U256>,
    pub is_critical: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DependencyType {
    ReadDependency,     // Reads state from other contract
    WriteDependency,    // Writes to state read by other contract
    CallDependency,     // Calls function that modifies state
    ProxyDependency,    // Proxy/implementation relationship
    OracleDependency,   // Depends on oracle data
}

/// A storage access operation
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageAccess {
    pub slot: U256,
    pub access_type: AccessType,
    pub accessed_from: Option<H160>, // Which contract initiated this
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessType {
    Read,
    Write,
    ReadWrite,
}

/// State shared between multiple contracts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedState {
    pub storage_slot: U256,
    pub owner_contract: H160,
    pub accessor_contracts: Vec<H160>,
    pub conflict_risk: ConflictRisk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictRisk {
    Low,        // Read-only access
    Medium,     // Sequential writes
    High,       // Concurrent writes possible
    Critical,   // Race condition detected
}

/// Result of state dependency analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyAnalysisResult {
    pub total_dependencies: usize,
    pub critical_dependencies: usize,
    pub shared_state_count: usize,
    pub high_risk_shared_state: Vec<SharedState>,
    pub dependency_graph: HashMap<H160, Vec<H160>>, // Contract -> its dependencies
    pub circular_dependencies: Vec<Vec<H160>>,
}

impl StateDependencyAnalyzer {
    pub fn new() -> Self {
        Self {
            dependencies: Vec::new(),
            storage_access: HashMap::new(),
            shared_state: Vec::new(),
        }
    }

    /// Record a storage access
    pub fn record_access(
        &mut self,
        contract: H160,
        slot: U256,
        access_type: AccessType,
        accessed_from: Option<H160>,
    ) {
        let access = StorageAccess {
            slot,
            access_type,
            accessed_from,
        };

        self.storage_access.entry(contract)
            .or_insert_with(HashSet::new)
            .insert(access);
    }

    /// Add a state dependency
    pub fn add_dependency(&mut self, dependency: StateDependency) {
        self.dependencies.push(dependency);
    }

    /// Analyze storage access patterns to find shared state
    pub fn analyze_shared_state(&mut self) {
        let mut slot_access: HashMap<(H160, U256), Vec<(H160, AccessType)>> = HashMap::new();

        // Collect all accesses to each slot
        for (contract, accesses) in &self.storage_access {
            for access in accesses {
                let key = (*contract, access.slot);
                slot_access.entry(key)
                    .or_insert_with(Vec::new)
                    .push((
                        access.accessed_from.unwrap_or(*contract),
                        access.access_type.clone(),
                    ));
            }
        }

        // Find slots accessed by multiple contracts
        for ((owner, slot), accessors) in slot_access {
            if accessors.len() > 1 {
                let accessor_contracts: Vec<H160> = accessors.iter()
                    .map(|(addr, _)| *addr)
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();

                if accessor_contracts.len() > 1 {
                    let conflict_risk = self.assess_conflict_risk(&accessors);

                    self.shared_state.push(SharedState {
                        storage_slot: slot,
                        owner_contract: owner,
                        accessor_contracts,
                        conflict_risk,
                    });
                }
            }
        }
    }

    /// Assess the conflict risk for a set of accesses
    fn assess_conflict_risk(&self, accesses: &[(H160, AccessType)]) -> ConflictRisk {
        let has_write = accesses.iter()
            .any(|(_, t)| matches!(t, AccessType::Write | AccessType::ReadWrite));

        let write_count = accesses.iter()
            .filter(|(_, t)| matches!(t, AccessType::Write | AccessType::ReadWrite))
            .count();

        if write_count > 1 {
            ConflictRisk::Critical // Multiple writers - race condition!
        } else if has_write {
            ConflictRisk::High // Single writer, multiple readers
        } else {
            ConflictRisk::Low // All reads
        }
    }

    /// Find dependencies where contract A reads state written by contract B
    pub fn find_read_write_dependencies(&mut self) {
        let mut writers: HashMap<(H160, U256), Vec<H160>> = HashMap::new();
        let mut readers: HashMap<(H160, U256), Vec<H160>> = HashMap::new();

        // Collect writers and readers
        for (contract, accesses) in &self.storage_access {
            for access in accesses {
                let key = (*contract, access.slot);
                
                match access.access_type {
                    AccessType::Write | AccessType::ReadWrite => {
                        writers.entry(key)
                            .or_insert_with(Vec::new)
                            .push(access.accessed_from.unwrap_or(*contract));
                    }
                    AccessType::Read => {
                        readers.entry(key)
                            .or_insert_with(Vec::new)
                            .push(access.accessed_from.unwrap_or(*contract));
                    }
                }
            }
        }

        // Find read-after-write dependencies
        for ((contract, slot), reader_list) in &readers {
            if let Some(writer_list) = writers.get(&(*contract, *slot)) {
                for reader in reader_list {
                    for writer in writer_list {
                        if reader != writer {
                            self.add_dependency(StateDependency {
                                dependent_contract: *reader,
                                dependency_contract: *writer,
                                dependency_type: DependencyType::ReadDependency,
                                storage_slots: vec![*slot],
                                is_critical: false,
                            });
                        }
                    }
                }
            }
        }
    }

    /// Detect circular dependencies
    pub fn find_circular_dependencies(&self) -> Vec<Vec<H160>> {
        let mut graph: HashMap<H160, Vec<H160>> = HashMap::new();

        // Build dependency graph
        for dep in &self.dependencies {
            graph.entry(dep.dependent_contract)
                .or_insert_with(Vec::new)
                .push(dep.dependency_contract);
        }

        // Find cycles using DFS
        let mut cycles = Vec::new();
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        let mut path = Vec::new();

        for node in graph.keys() {
            if !visited.contains(node) {
                self.dfs_find_cycles(
                    *node,
                    &graph,
                    &mut visited,
                    &mut rec_stack,
                    &mut path,
                    &mut cycles,
                );
            }
        }

        cycles
    }

    fn dfs_find_cycles(
        &self,
        node: H160,
        graph: &HashMap<H160, Vec<H160>>,
        visited: &mut HashSet<H160>,
        rec_stack: &mut HashSet<H160>,
        path: &mut Vec<H160>,
        cycles: &mut Vec<Vec<H160>>,
    ) {
        visited.insert(node);
        rec_stack.insert(node);
        path.push(node);

        if let Some(neighbors) = graph.get(&node) {
            for &neighbor in neighbors {
                if !visited.contains(&neighbor) {
                    self.dfs_find_cycles(neighbor, graph, visited, rec_stack, path, cycles);
                } else if rec_stack.contains(&neighbor) {
                    // Found a cycle
                    if let Some(start) = path.iter().position(|&n| n == neighbor) {
                        let cycle = path[start..].to_vec();
                        cycles.push(cycle);
                    }
                }
            }
        }

        path.pop();
        rec_stack.remove(&node);
    }

    /// Perform complete analysis and return results
    pub fn analyze(&mut self) -> DependencyAnalysisResult {
        // Analyze shared state
        self.analyze_shared_state();

        // Find read-write dependencies
        self.find_read_write_dependencies();

        // Find circular dependencies
        let circular_dependencies = self.find_circular_dependencies();

        // Build dependency graph
        let mut dependency_graph: HashMap<H160, Vec<H160>> = HashMap::new();
        for dep in &self.dependencies {
            dependency_graph.entry(dep.dependent_contract)
                .or_insert_with(Vec::new)
                .push(dep.dependency_contract);
        }

        // Count critical dependencies
        let critical_dependencies = self.dependencies.iter()
            .filter(|d| d.is_critical)
            .count();

        // Find high-risk shared state
        let high_risk_shared_state: Vec<SharedState> = self.shared_state.iter()
            .filter(|s| matches!(s.conflict_risk, ConflictRisk::High | ConflictRisk::Critical))
            .cloned()
            .collect();

        DependencyAnalysisResult {
            total_dependencies: self.dependencies.len(),
            critical_dependencies,
            shared_state_count: self.shared_state.len(),
            high_risk_shared_state,
            dependency_graph,
            circular_dependencies,
        }
    }

    /// Get all dependencies for a contract
    pub fn get_dependencies(&self, contract: H160) -> Vec<&StateDependency> {
        self.dependencies.iter()
            .filter(|d| d.dependent_contract == contract || d.dependency_contract == contract)
            .collect()
    }

    /// Clear all tracked data
    pub fn clear(&mut self) {
        self.dependencies.clear();
        self.storage_access.clear();
        self.shared_state.clear();
    }
}

impl Default for StateDependencyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_access_recording() {
        let mut analyzer = StateDependencyAnalyzer::new();
        let contract = H160::random();
        let slot = U256::from(0);

        analyzer.record_access(contract, slot, AccessType::Read, None);
        
        assert!(analyzer.storage_access.contains_key(&contract));
    }

    #[test]
    fn test_shared_state_detection() {
        let mut analyzer = StateDependencyAnalyzer::new();
        let contract1 = H160::random();
        let contract2 = H160::random();
        let slot = U256::from(5);

        // Both contracts access same slot
        analyzer.record_access(contract1, slot, AccessType::Read, Some(contract2));
        analyzer.record_access(contract1, slot, AccessType::Write, Some(contract1));

        analyzer.analyze_shared_state();

        assert!(!analyzer.shared_state.is_empty());
    }

    #[test]
    fn test_conflict_risk_assessment() {
        let analyzer = StateDependencyAnalyzer::new();
        
        // Multiple writers = critical
        let accesses = vec![
            (H160::random(), AccessType::Write),
            (H160::random(), AccessType::Write),
        ];
        let risk = analyzer.assess_conflict_risk(&accesses);
        assert_eq!(risk, ConflictRisk::Critical);

        // Single writer, reader = high
        let accesses2 = vec![
            (H160::random(), AccessType::Write),
            (H160::random(), AccessType::Read),
        ];
        let risk2 = analyzer.assess_conflict_risk(&accesses2);
        assert_eq!(risk2, ConflictRisk::High);
    }
}
