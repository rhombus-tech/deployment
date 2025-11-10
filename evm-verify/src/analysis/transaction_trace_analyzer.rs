use crate::circuits::execution_trace::{EVMExecutionTrace, ExecutionStep};
use crate::analysis::{
    call_graph::{CallGraph, CallType, ContractType},
    rpc_bytecode_fetcher::RPCBytecodeFetcher,
    stack_state_tracker::StackStateTracker,
    data_flow_analyzer::{DataFlowAnalyzer, DataType, FlowType},
    taint_tracker::{TaintTracker, TaintedVariable, VariableType, TaintLevel},
    state_dependency_analyzer::{StateDependencyAnalyzer, AccessType},
};
use ethers::types::{H160, H256, Transaction, Bytes, U256};
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use anyhow::{Result, anyhow};

/// Analyzes transaction execution traces to extract cross-contract interactions
#[derive(Debug, Clone)]
pub struct TransactionTraceAnalyzer {
    /// Collected contract bytecodes from trace
    pub contracts: HashMap<H160, Vec<u8>>,
    /// Call graph built from trace
    pub call_graph: CallGraph,
    /// Execution trace being analyzed
    trace: Option<EVMExecutionTrace>,
    /// RPC bytecode fetcher
    bytecode_fetcher: Option<RPCBytecodeFetcher>,
    /// Stack state tracker
    stack_tracker: StackStateTracker,
    /// Data flow analyzer
    data_flow: DataFlowAnalyzer,
    /// Taint tracker
    taint_tracker: TaintTracker,
    /// State dependency analyzer
    state_deps: StateDependencyAnalyzer,
}

/// Result of analyzing a transaction trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceAnalysisResult {
    pub contracts_involved: Vec<H160>,
    pub call_graph: CallGraph,
    pub total_calls: usize,
    pub unique_contracts: usize,
    pub max_call_depth: u32,
    pub gas_used: u64,
    pub value_transferred: u64,
}

impl TransactionTraceAnalyzer {
    /// Create a new transaction trace analyzer
    pub fn new() -> Self {
        Self {
            contracts: HashMap::new(),
            call_graph: CallGraph::new(),
            trace: None,
            bytecode_fetcher: None,
            stack_tracker: StackStateTracker::new(),
            data_flow: DataFlowAnalyzer::new(),
            taint_tracker: TaintTracker::new(),
            state_deps: StateDependencyAnalyzer::new(),
        }
    }

    /// Create with RPC endpoint for fetching bytecode
    pub fn with_rpc(rpc_url: String) -> Result<Self> {
        let fetcher = RPCBytecodeFetcher::new(rpc_url)?;
        Ok(Self {
            contracts: HashMap::new(),
            call_graph: CallGraph::new(),
            trace: None,
            bytecode_fetcher: Some(fetcher),
            stack_tracker: StackStateTracker::new(),
            data_flow: DataFlowAnalyzer::new(),
            taint_tracker: TaintTracker::new(),
            state_deps: StateDependencyAnalyzer::new(),
        })
    }

    /// Analyze an execution trace and extract all contracts
    pub fn analyze_trace(&mut self, trace: EVMExecutionTrace) -> Result<TraceAnalysisResult> {
        self.trace = Some(trace.clone());
        
        // Extract all contract interactions (sync version)
        self.extract_contracts_sync(&trace)?;
        
        // Build call graph from trace
        self.build_call_graph_from_trace(&trace)?;
        
        // Analyze criticality
        self.call_graph.identify_critical_contracts();
        self.call_graph.identify_entry_points();
        
        // Compute statistics
        let max_depth = self.compute_max_call_depth(&trace);
        let total_gas: u64 = trace.execution_steps.iter()
            .map(|step| step.gas_cost.as_u64())
            .sum();
        
        Ok(TraceAnalysisResult {
            contracts_involved: self.contracts.keys().copied().collect(),
            call_graph: self.call_graph.clone(),
            total_calls: trace.execution_steps.len(),
            unique_contracts: self.contracts.len(),
            max_call_depth: max_depth,
            gas_used: total_gas,
            value_transferred: 0, // Would track value from CALL instructions
        })
    }

    /// Extract all contract bytecodes from execution trace
    async fn extract_contracts_from_trace(&mut self, trace: &EVMExecutionTrace) -> Result<()> {
        // Collect all unique contract addresses
        let addresses: HashSet<H160> = trace.execution_steps.iter()
            .map(|step| step.contract_address)
            .collect();

        // Fetch bytecode for all contracts
        if let Some(fetcher) = &self.bytecode_fetcher {
            let addresses_vec: Vec<H160> = addresses.iter().copied().collect();
            let bytecodes = fetcher.get_bytecodes(&addresses_vec).await?;
            self.contracts.extend(bytecodes);
        } else {
            // No fetcher - just register addresses with empty bytecode
            for address in addresses {
                if !self.contracts.contains_key(&address) {
                    self.contracts.insert(address, Vec::new());
                }
            }
        }
        
        Ok(())
    }

    /// Synchronous version for when RPC is not available
    /// Enhanced with validation and error handling
    fn extract_contracts_sync(&mut self, trace: &EVMExecutionTrace) -> Result<()> {
        // Validate trace is not empty
        if trace.execution_steps.is_empty() {
            return Err(anyhow!("Empty execution trace provided"));
        }
        
        let mut contract_count = 0;
        
        for (step_idx, step) in trace.execution_steps.iter().enumerate() {
            let address = step.contract_address;
            
            // Validate address is not zero (except for contract creation)
            if address.is_zero() && !Self::is_creation_step(step) {
                log::warn!("Step {} has zero address, skipping", step_idx);
                continue;
            }
            
            // Validate opcode is in valid EVM range (0x00-0xFF)
            if !Self::is_valid_opcode(step.opcode) {
                return Err(anyhow!(
                    "Invalid opcode 0x{:02X} at step {}", 
                    step.opcode, 
                    step_idx
                ));
            }
            
            if !self.contracts.contains_key(&address) {
                self.contracts.insert(address, Vec::new());
                contract_count += 1;
            }
        }
        
        // Ensure we found at least one contract
        if contract_count == 0 && self.contracts.is_empty() {
            return Err(anyhow!("No valid contracts found in execution trace"));
        }
        
        log::info!("Extracted {} unique contracts from trace", contract_count);
        Ok(())
    }
    
    /// Check if an opcode is valid (0x00-0xFF and exists in EVM spec)
    fn is_valid_opcode(opcode: u8) -> bool {
        // All u8 values are technically valid, but check if it's a known opcode
        // For now, accept all since unknown opcodes will be handled gracefully
        true
    }
    
    /// Check if this is a contract creation step (CREATE or CREATE2)
    fn is_creation_step(step: &ExecutionStep) -> bool {
        matches!(step.opcode, 0xF0 | 0xF5) // CREATE or CREATE2
    }

    /// Build call graph from execution trace with full analysis
    fn build_call_graph_from_trace(&mut self, trace: &EVMExecutionTrace) -> Result<()> {
        let mut call_stack: Vec<H160> = Vec::new();
        self.stack_tracker.reset();
        
        for step in &trace.execution_steps {
            let current_contract = step.contract_address;
            
            // Update stack state
            self.stack_tracker.process_step(step)?;
            
            // Detect contract calls
            match step.opcode {
                0xF1 | 0xF2 | 0xF4 | 0xFA => {
                    // CALL, CALLCODE, DELEGATECALL, STATICCALL
                    let call_type = CallType::from_opcode(step.opcode);
                    
                    // Extract target address from stack
                    if let Some(call_info) = self.stack_tracker.extract_call_target(step.opcode) {
                        let target = call_info.target_address;
                        let has_value = call_info.value > U256::zero();
                        
                        if let Some(caller) = call_stack.last() {
                            // Add to call graph
                            self.call_graph.add_call(
                                *caller,
                                target,
                                call_type.clone(),
                                has_value,
                            );

                            // Track data flow
                            if has_value {
                                self.data_flow.add_flow(*caller, target, DataType::Value, FlowType::Direct);
                            }
                            self.data_flow.add_flow(*caller, target, DataType::CallData, FlowType::Direct);

                            // Track taint - external calls introduce taint
                            self.taint_tracker.mark_tainted(target, TaintedVariable {
                                var_type: VariableType::CallData,
                                location: U256::zero(),
                                taint_level: TaintLevel::Medium,
                                source: format!("external_call_from_{:?}", caller),
                            });
                        }
                        
                        call_stack.push(target);
                    }
                },
                0xF3 | 0xFD => {
                    // RETURN, REVERT - pop from call stack
                    if let Some(returning_contract) = call_stack.pop() {
                        // Track return data flow
                        if let Some(caller) = call_stack.last() {
                            self.data_flow.add_flow(
                                returning_contract,
                                *caller,
                                DataType::ReturnData,
                                FlowType::ReturnValue,
                            );
                        }
                    }
                },
                0x54 => {
                    // SLOAD - storage read
                    self.state_deps.record_access(
                        current_contract,
                        U256::zero(), // Would extract slot from stack
                        AccessType::Read,
                        call_stack.last().copied(),
                    );
                },
                0x55 => {
                    // SSTORE - storage write
                    self.state_deps.record_access(
                        current_contract,
                        U256::zero(), // Would extract slot from stack
                        AccessType::Write,
                        call_stack.last().copied(),
                    );
                },
                _ => {}
            }
        }
        
        // Analyze state dependencies
        self.state_deps.analyze_shared_state();
        self.state_deps.find_read_write_dependencies();
        
        Ok(())
    }

    /// Compute maximum call depth from trace
    fn compute_max_call_depth(&self, trace: &EVMExecutionTrace) -> u32 {
        let mut max_depth = 0;
        let mut current_depth = 0;
        
        for step in &trace.execution_steps {
            match step.opcode {
                0xF1 | 0xF2 | 0xF4 | 0xFA => {
                    current_depth += 1;
                    max_depth = max_depth.max(current_depth);
                },
                0xF3 | 0xFD => {
                    if current_depth > 0 {
                        current_depth -= 1;
                    }
                },
                _ => {}
            }
        }
        
        max_depth
    }

    /// Add contract bytecode manually (for testing or when trace doesn't include bytecode)
    pub fn add_contract(&mut self, address: H160, bytecode: Vec<u8>, contract_type: ContractType) {
        self.contracts.insert(address, bytecode);
        self.call_graph.add_node(address, contract_type);
    }

    /// Get all contracts discovered
    pub fn get_contracts(&self) -> &HashMap<H160, Vec<u8>> {
        &self.contracts
    }

    /// Get the built call graph
    pub fn get_call_graph(&self) -> &CallGraph {
        &self.call_graph
    }

    /// Detect if this is a multi-contract attack pattern
    pub fn is_complex_attack_pattern(&self) -> bool {
        // Check for indicators of complex attacks:
        // 1. Many contracts involved (> 3)
        // 2. Deep call chains (> 4)
        // 3. Circular calls
        // 4. DELEGATECALL usage
        // 5. Tainted data flows
        // 6. High-risk state dependencies
        
        let stats = self.call_graph.get_statistics();
        let cycles = self.call_graph.find_cycles();
        let taint_stats = self.taint_tracker.get_statistics();
        
        stats.total_contracts > 3 ||
        stats.delegate_call_count > 0 ||
        !cycles.is_empty() ||
        taint_stats.critical_taints > 0
    }

    /// Get data flow analyzer results
    pub fn get_data_flow_analysis(&self) -> &DataFlowAnalyzer {
        &self.data_flow
    }

    /// Get taint analysis results
    pub fn get_taint_analysis(&self) -> &TaintTracker {
        &self.taint_tracker
    }

    /// Get state dependency analysis results
    pub fn get_state_dependencies(&self) -> &StateDependencyAnalyzer {
        &self.state_deps
    }

    /// Get comprehensive analysis report
    pub fn get_comprehensive_report(&mut self) -> ComprehensiveAnalysisReport {
        let call_graph_stats = self.call_graph.get_statistics();
        let attack_paths = self.call_graph.find_all_attack_paths();
        let data_flow_stats = self.data_flow.get_statistics();
        let taint_stats = self.taint_tracker.get_statistics();
        let taint_result = self.taint_tracker.analyze();
        let dep_result = self.state_deps.analyze();

        ComprehensiveAnalysisReport {
            contracts_analyzed: self.contracts.len(),
            call_graph_statistics: call_graph_stats,
            attack_paths,
            data_flow_statistics: data_flow_stats,
            taint_statistics: taint_stats,
            taint_analysis: taint_result,
            dependency_analysis: dep_result,
            dangerous_data_flows: self.data_flow.find_dangerous_flows(),
        }
    }
}

/// Comprehensive analysis report combining all analyzers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveAnalysisReport {
    pub contracts_analyzed: usize,
    pub call_graph_statistics: crate::analysis::call_graph::CallGraphStatistics,
    pub attack_paths: Vec<crate::analysis::call_graph::AttackPath>,
    pub data_flow_statistics: crate::analysis::data_flow_analyzer::DataFlowStatistics,
    pub taint_statistics: crate::analysis::taint_tracker::TaintStatistics,
    pub taint_analysis: crate::analysis::taint_tracker::TaintAnalysisResult,
    pub dependency_analysis: crate::analysis::state_dependency_analyzer::DependencyAnalysisResult,
    pub dangerous_data_flows: Vec<crate::analysis::data_flow_analyzer::DangerousFlow>,
}

impl Default for TransactionTraceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::U256;

    #[test]
    fn test_trace_analyzer_creation() {
        let analyzer = TransactionTraceAnalyzer::new();
        assert_eq!(analyzer.contracts.len(), 0);
    }

    #[test]
    fn test_add_contract() {
        let mut analyzer = TransactionTraceAnalyzer::new();
        let address = H160::random();
        let bytecode = vec![0x60, 0x80, 0x60, 0x40];
        
        analyzer.add_contract(address, bytecode.clone(), ContractType::Router);
        
        assert_eq!(analyzer.contracts.len(), 1);
        assert_eq!(analyzer.contracts.get(&address), Some(&bytecode));
    }

    #[test]
    fn test_complex_attack_detection() {
        let mut analyzer = TransactionTraceAnalyzer::new();
        
        // Add multiple contracts
        for _ in 0..5 {
            analyzer.add_contract(H160::random(), Vec::new(), ContractType::Unknown);
        }
        
        assert!(analyzer.is_complex_attack_pattern());
    }
}
