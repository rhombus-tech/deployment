use ethers::types::{H160, U256};
use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};

/// Tracks tainted data throughout cross-contract execution
#[derive(Debug, Clone)]
pub struct TaintTracker {
    /// Tainted variables by contract
    tainted_vars: HashMap<H160, HashSet<TaintedVariable>>,
    /// Propagation rules
    propagation_rules: Vec<PropagationRule>,
    /// Taint sources (where taint originates)
    taint_sources: Vec<TaintSource>,
}

/// A tainted variable in a contract
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintedVariable {
    pub var_type: VariableType,
    pub location: U256,
    pub taint_level: TaintLevel,
    pub source: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum VariableType {
    Storage,
    Memory,
    Stack,
    CallData,
    ReturnData,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TaintLevel {
    Low,        // Indirectly tainted
    Medium,     // Direct taint from external source
    High,       // Taint from untrusted source
    Critical,   // Taint from malicious source
}

/// Source of taint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintSource {
    pub contract: H160,
    pub source_type: TaintSourceType,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaintSourceType {
    UserInput,          // msg.sender, tx.origin
    ExternalCall,       // Return from external contract
    UntrustedContract,  // Call from unknown contract
    PublicStorage,      // Publicly writable storage
    Event,              // Event emission
}

/// Rule for how taint propagates
#[derive(Debug, Clone)]
pub struct PropagationRule {
    pub from_type: VariableType,
    pub to_type: VariableType,
    pub operation: String,
    pub taint_preserved: bool,
}

/// Result of taint analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintAnalysisResult {
    pub total_tainted_vars: usize,
    pub tainted_by_contract: HashMap<H160, usize>,
    pub critical_taint_flows: Vec<CriticalTaintFlow>,
    pub high_risk_contracts: Vec<H160>,
}

/// A critical flow of tainted data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalTaintFlow {
    pub from_contract: H160,
    pub to_contract: H160,
    pub tainted_var: TaintedVariable,
    pub propagation_path: Vec<String>,
    pub danger_level: TaintLevel,
}

impl TaintTracker {
    pub fn new() -> Self {
        let mut tracker = Self {
            tainted_vars: HashMap::new(),
            propagation_rules: Vec::new(),
            taint_sources: Vec::new(),
        };
        
        // Initialize default propagation rules
        tracker.init_default_rules();
        
        tracker
    }

    /// Initialize default taint propagation rules
    fn init_default_rules(&mut self) {
        // CallData taints Stack
        self.propagation_rules.push(PropagationRule {
            from_type: VariableType::CallData,
            to_type: VariableType::Stack,
            operation: "CALLDATALOAD".to_string(),
            taint_preserved: true,
        });

        // Stack taints Memory
        self.propagation_rules.push(PropagationRule {
            from_type: VariableType::Stack,
            to_type: VariableType::Memory,
            operation: "MSTORE".to_string(),
            taint_preserved: true,
        });

        // Memory taints Storage
        self.propagation_rules.push(PropagationRule {
            from_type: VariableType::Memory,
            to_type: VariableType::Storage,
            operation: "SSTORE".to_string(),
            taint_preserved: true,
        });

        // ReturnData taints Stack
        self.propagation_rules.push(PropagationRule {
            from_type: VariableType::ReturnData,
            to_type: VariableType::Stack,
            operation: "RETURNDATALOAD".to_string(),
            taint_preserved: true,
        });
    }

    /// Mark a variable as tainted
    pub fn mark_tainted(
        &mut self,
        contract: H160,
        var: TaintedVariable,
    ) {
        self.tainted_vars.entry(contract)
            .or_insert_with(HashSet::new)
            .insert(var);
    }

    /// Check if a variable is tainted
    pub fn is_tainted(
        &self,
        contract: H160,
        var_type: VariableType,
        location: U256,
    ) -> bool {
        if let Some(vars) = self.tainted_vars.get(&contract) {
            vars.iter().any(|v| v.var_type == var_type && v.location == location)
        } else {
            false
        }
    }

    /// Get taint level of a variable
    pub fn get_taint_level(
        &self,
        contract: H160,
        var_type: VariableType,
        location: U256,
    ) -> Option<TaintLevel> {
        if let Some(vars) = self.tainted_vars.get(&contract) {
            vars.iter()
                .find(|v| v.var_type == var_type && v.location == location)
                .map(|v| v.taint_level.clone())
        } else {
            None
        }
    }

    /// Add a taint source
    pub fn add_source(&mut self, source: TaintSource) {
        self.taint_sources.push(source);
    }

    /// Propagate taint based on operation
    pub fn propagate_taint(
        &mut self,
        contract: H160,
        from_var: &TaintedVariable,
        to_type: VariableType,
        to_location: U256,
        operation: &str,
    ) {
        // Check if there's a matching propagation rule
        let should_propagate = self.propagation_rules.iter()
            .any(|rule| {
                rule.from_type == from_var.var_type &&
                rule.to_type == to_type &&
                rule.operation == operation &&
                rule.taint_preserved
            });

        if should_propagate {
            let new_tainted = TaintedVariable {
                var_type: to_type,
                location: to_location,
                taint_level: from_var.taint_level.clone(),
                source: from_var.source.clone(),
            };
            self.mark_tainted(contract, new_tainted);
        }
    }

    /// Find critical taint flows across contracts
    pub fn find_critical_flows(&self) -> Vec<CriticalTaintFlow> {
        let mut critical_flows = Vec::new();

        // Look for high/critical taint that crosses contracts
        for (contract, vars) in &self.tainted_vars {
            for var in vars {
                if matches!(var.taint_level, TaintLevel::High | TaintLevel::Critical) {
                    // This is a critical taint - track where it goes
                    // In real implementation, would trace through call graph
                    // For now, mark as potential critical flow
                }
            }
        }

        critical_flows
    }

    /// Analyze all taint and produce report
    pub fn analyze(&self) -> TaintAnalysisResult {
        let total_tainted_vars = self.tainted_vars.values()
            .map(|v| v.len())
            .sum();

        let mut tainted_by_contract = HashMap::new();
        for (contract, vars) in &self.tainted_vars {
            tainted_by_contract.insert(*contract, vars.len());
        }

        let critical_taint_flows = self.find_critical_flows();

        // Find high-risk contracts (many tainted variables)
        let high_risk_contracts: Vec<H160> = self.tainted_vars.iter()
            .filter(|(_, vars)| vars.len() > 5) // Threshold: > 5 tainted vars
            .map(|(addr, _)| *addr)
            .collect();

        TaintAnalysisResult {
            total_tainted_vars,
            tainted_by_contract,
            critical_taint_flows,
            high_risk_contracts,
        }
    }

    /// Get all tainted variables for a contract
    pub fn get_tainted_vars(&self, contract: H160) -> Option<&HashSet<TaintedVariable>> {
        self.tainted_vars.get(&contract)
    }

    /// Clear all taint tracking
    pub fn clear(&mut self) {
        self.tainted_vars.clear();
        self.taint_sources.clear();
    }

    /// Get statistics
    pub fn get_statistics(&self) -> TaintStatistics {
        let total_vars = self.tainted_vars.values().map(|v| v.len()).sum();
        
        let critical_count = self.tainted_vars.values()
            .flat_map(|vars| vars.iter())
            .filter(|v| v.taint_level == TaintLevel::Critical)
            .count();

        let high_count = self.tainted_vars.values()
            .flat_map(|vars| vars.iter())
            .filter(|v| v.taint_level == TaintLevel::High)
            .count();

        TaintStatistics {
            total_tainted_variables: total_vars,
            contracts_with_taint: self.tainted_vars.len(),
            critical_taints: critical_count,
            high_taints: high_count,
            taint_sources: self.taint_sources.len(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintStatistics {
    pub total_tainted_variables: usize,
    pub contracts_with_taint: usize,
    pub critical_taints: usize,
    pub high_taints: usize,
    pub taint_sources: usize,
}

impl Default for TaintTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_marking() {
        let mut tracker = TaintTracker::new();
        let contract = H160::random();
        let var = TaintedVariable {
            var_type: VariableType::Storage,
            location: U256::from(0),
            taint_level: TaintLevel::High,
            source: "user_input".to_string(),
        };

        tracker.mark_tainted(contract, var.clone());
        assert!(tracker.is_tainted(contract, VariableType::Storage, U256::from(0)));
    }

    #[test]
    fn test_taint_level() {
        let mut tracker = TaintTracker::new();
        let contract = H160::random();
        let var = TaintedVariable {
            var_type: VariableType::Stack,
            location: U256::from(5),
            taint_level: TaintLevel::Critical,
            source: "external_call".to_string(),
        };

        tracker.mark_tainted(contract, var);
        let level = tracker.get_taint_level(contract, VariableType::Stack, U256::from(5));
        assert_eq!(level, Some(TaintLevel::Critical));
    }

    #[test]
    fn test_taint_propagation() {
        let mut tracker = TaintTracker::new();
        let contract = H160::random();
        
        let source_var = TaintedVariable {
            var_type: VariableType::CallData,
            location: U256::from(0),
            taint_level: TaintLevel::High,
            source: "user_input".to_string(),
        };

        tracker.mark_tainted(contract, source_var.clone());
        
        // Propagate to stack
        tracker.propagate_taint(
            contract,
            &source_var,
            VariableType::Stack,
            U256::from(0),
            "CALLDATALOAD",
        );

        assert!(tracker.is_tainted(contract, VariableType::Stack, U256::from(0)));
    }
}
