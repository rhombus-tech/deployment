use ethers::types::{H160, H256, U256};
use std::collections::{HashMap, HashSet};
use serde::{Serialize, Deserialize};

/// Tracks data flow between contracts
#[derive(Debug, Clone)]
pub struct DataFlowAnalyzer {
    /// Data flows between contracts
    flows: Vec<DataFlow>,
    /// Data sources (where data originates)
    sources: HashMap<H160, Vec<DataSource>>,
    /// Data sinks (where data is used)
    sinks: HashMap<H160, Vec<DataSink>>,
    /// Tainted data tracking
    tainted_data: HashSet<DataIdentifier>,
}

/// Represents a flow of data from one contract to another
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlow {
    pub from_contract: H160,
    pub to_contract: H160,
    pub data_type: DataType,
    pub flow_type: FlowType,
    pub is_sensitive: bool,
    pub is_tainted: bool,
}

/// Type of data being transferred
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataType {
    Value,          // ETH/token value
    CallData,       // Function call data
    ReturnData,     // Return value from call
    StorageValue,   // Storage slot value
    EventData,      // Event log data
}

/// How the data flows
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowType {
    Direct,         // Direct parameter passing
    Storage,        // Via storage read/write
    Event,          // Via event emission
    ReturnValue,    // Via return value
}

/// Source of data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSource {
    pub contract: H160,
    pub source_type: SourceType,
    pub location: DataLocation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceType {
    UserInput,      // From transaction sender
    Storage,        // From contract storage
    External,       // From external contract
    Computed,       // Computed value
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataLocation {
    pub contract: H160,
    pub slot_or_pc: U256,
}

/// Where data is consumed/used
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSink {
    pub contract: H160,
    pub sink_type: SinkType,
    pub location: DataLocation,
    pub is_dangerous: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SinkType {
    Transfer,       // Value transfer (CALL with value)
    DelegateCall,   // DELEGATECALL target
    StorageWrite,   // SSTORE
    EventEmit,      // LOG
    SelfDestruct,   // SELFDESTRUCT
}

/// Unique identifier for a piece of data
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct DataIdentifier {
    pub contract: H160,
    pub location: U256,
    pub data_type: String,
}

impl DataFlowAnalyzer {
    pub fn new() -> Self {
        Self {
            flows: Vec::new(),
            sources: HashMap::new(),
            sinks: HashMap::new(),
            tainted_data: HashSet::new(),
        }
    }

    /// Track a data flow between contracts
    pub fn add_flow(
        &mut self,
        from: H160,
        to: H160,
        data_type: DataType,
        flow_type: FlowType,
    ) {
        let is_sensitive = self.is_sensitive_data_type(&data_type);
        let is_tainted = self.is_flow_tainted(from, to);

        self.flows.push(DataFlow {
            from_contract: from,
            to_contract: to,
            data_type,
            flow_type,
            is_sensitive,
            is_tainted,
        });
    }

    /// Mark data as tainted (potentially dangerous)
    pub fn mark_tainted(&mut self, identifier: DataIdentifier) {
        self.tainted_data.insert(identifier);
    }

    /// Check if data is tainted
    pub fn is_tainted(&self, identifier: &DataIdentifier) -> bool {
        self.tainted_data.contains(identifier)
    }

    /// Add a data source
    pub fn add_source(&mut self, source: DataSource) {
        self.sources.entry(source.contract)
            .or_insert_with(Vec::new)
            .push(source);
    }

    /// Add a data sink
    pub fn add_sink(&mut self, sink: DataSink) {
        self.sinks.entry(sink.contract)
            .or_insert_with(Vec::new)
            .push(sink);
    }

    /// Find all paths from sources to dangerous sinks
    pub fn find_dangerous_flows(&self) -> Vec<DangerousFlow> {
        let mut dangerous = Vec::new();

        for sink_contract in self.sinks.keys() {
            if let Some(sinks_list) = self.sinks.get(sink_contract) {
                for sink in sinks_list {
                    if sink.is_dangerous {
                        // Find flows leading to this sink
                        let leading_flows = self.find_flows_to_sink(*sink_contract);
                        if !leading_flows.is_empty() {
                            let severity = self.calculate_flow_severity(&leading_flows, sink);
                            dangerous.push(DangerousFlow {
                                path: leading_flows,
                                sink: sink.clone(),
                                severity,
                            });
                        }
                    }
                }
            }
        }

        dangerous
    }

    /// Find all flows leading to a specific contract
    fn find_flows_to_sink(&self, target: H160) -> Vec<DataFlow> {
        self.flows.iter()
            .filter(|flow| flow.to_contract == target)
            .cloned()
            .collect()
    }

    /// Calculate severity of a dangerous flow
    fn calculate_flow_severity(&self, flows: &[DataFlow], sink: &DataSink) -> FlowSeverity {
        let has_tainted = flows.iter().any(|f| f.is_tainted);
        let has_sensitive = flows.iter().any(|f| f.is_sensitive);

        match sink.sink_type {
            SinkType::SelfDestruct => FlowSeverity::Critical,
            SinkType::DelegateCall if has_tainted => FlowSeverity::Critical,
            SinkType::Transfer if has_sensitive => FlowSeverity::High,
            SinkType::DelegateCall => FlowSeverity::High,
            SinkType::StorageWrite if has_tainted => FlowSeverity::Medium,
            _ => FlowSeverity::Low,
        }
    }

    fn is_sensitive_data_type(&self, data_type: &DataType) -> bool {
        matches!(data_type, DataType::Value | DataType::CallData)
    }

    fn is_flow_tainted(&self, from: H160, to: H160) -> bool {
        // Check if any data from 'from' contract is tainted
        self.tainted_data.iter()
            .any(|id| id.contract == from)
    }

    /// Get all flows for a contract
    pub fn get_contract_flows(&self, contract: H160) -> Vec<&DataFlow> {
        self.flows.iter()
            .filter(|f| f.from_contract == contract || f.to_contract == contract)
            .collect()
    }

    /// Get statistics
    pub fn get_statistics(&self) -> DataFlowStatistics {
        DataFlowStatistics {
            total_flows: self.flows.len(),
            tainted_flows: self.flows.iter().filter(|f| f.is_tainted).count(),
            sensitive_flows: self.flows.iter().filter(|f| f.is_sensitive).count(),
            total_sources: self.sources.values().map(|v| v.len()).sum(),
            total_sinks: self.sinks.values().map(|v| v.len()).sum(),
            dangerous_sinks: self.sinks.values()
                .flat_map(|v| v.iter())
                .filter(|s| s.is_dangerous)
                .count(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DangerousFlow {
    pub path: Vec<DataFlow>,
    pub sink: DataSink,
    pub severity: FlowSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FlowSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowStatistics {
    pub total_flows: usize,
    pub tainted_flows: usize,
    pub sensitive_flows: usize,
    pub total_sources: usize,
    pub total_sinks: usize,
    pub dangerous_sinks: usize,
}

impl Default for DataFlowAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_flow_creation() {
        let mut analyzer = DataFlowAnalyzer::new();
        let from = H160::random();
        let to = H160::random();
        
        analyzer.add_flow(from, to, DataType::Value, FlowType::Direct);
        
        assert_eq!(analyzer.flows.len(), 1);
    }

    #[test]
    fn test_taint_tracking() {
        let mut analyzer = DataFlowAnalyzer::new();
        let id = DataIdentifier {
            contract: H160::random(),
            location: U256::from(0),
            data_type: "value".to_string(),
        };
        
        assert!(!analyzer.is_tainted(&id));
        analyzer.mark_tainted(id.clone());
        assert!(analyzer.is_tainted(&id));
    }

    #[test]
    fn test_dangerous_flow_detection() {
        let mut analyzer = DataFlowAnalyzer::new();
        let contract = H160::random();
        
        // Add a dangerous sink
        analyzer.add_sink(DataSink {
            contract,
            sink_type: SinkType::SelfDestruct,
            location: DataLocation {
                contract,
                slot_or_pc: U256::from(100),
            },
            is_dangerous: true,
        });
        
        // Add flow to it
        analyzer.add_flow(
            H160::random(),
            contract,
            DataType::CallData,
            FlowType::Direct,
        );
        
        let dangerous = analyzer.find_dangerous_flows();
        assert!(!dangerous.is_empty());
    }
}
