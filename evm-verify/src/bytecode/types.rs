use ethers::types::{Bytes, H160, H256, Address, U256};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Analysis results for bytecode
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalysisResults {
    /// Constructor analysis
    pub constructor: ConstructorAnalysis,
    /// Runtime code analysis
    pub runtime: RuntimeAnalysis,
    /// Storage access patterns
    pub storage: Vec<StorageAccess>,
    /// Memory access patterns
    pub memory: MemoryAnalysis,
    /// Any safety warnings
    pub warnings: Vec<String>,
}

/// Constructor analysis data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConstructorAnalysis {
    /// Constructor arguments offset
    pub args_offset: usize,
    /// Constructor arguments length
    pub args_length: usize,
    /// Constructor parameter types
    pub param_types: Vec<String>,
    /// Code length
    pub code_length: usize,
}

/// Runtime code analysis data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeAnalysis {
    /// Runtime code offset
    pub code_offset: usize,
    /// Runtime code length
    pub code_length: usize,
    /// Initial storage slots
    pub initial_state: Vec<(H256, U256)>,
    /// Final storage slots
    pub final_state: Vec<(H256, U256)>,
    /// Memory accesses
    pub memory_accesses: Vec<MemoryAccess>,
    /// Memory allocations
    pub memory_allocations: Vec<MemoryAllocation>,
    /// Maximum memory size
    pub max_memory: usize,
    /// Contract caller
    pub caller: Address,
    /// Memory accesses
    pub memory_accesses_new: Vec<MemoryAccess>,
    /// Memory allocations
    pub memory_allocations_new: Vec<MemoryAllocation>,
    /// State transitions
    pub state_transitions: Vec<StateTransition>,
    /// Storage accesses
    pub storage_accesses: Vec<StorageAccess>,
    /// Access control checks
    pub access_checks: Vec<AccessControl>,
    /// Constructor calls
    pub constructor_calls: Vec<Constructor>,
}

/// Storage access information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageAccess {
    /// Storage slot being accessed
    pub slot: H256,
    /// Value being written (None for reads)
    pub value: Option<H256>,
    /// Whether this is an initialization
    pub is_init: bool,
    /// Program counter
    pub pc: u64,
    /// Write access
    pub write: bool,
}

/// Access control pattern
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccessPattern {
    /// Storage slot being protected
    pub protected_slot: H256,
    /// Address allowed to access (if specific)
    pub allowed_address: Option<H256>,
    /// Access control condition
    pub condition: String,
}

/// Memory access operation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryAccess {
    /// Memory offset
    pub offset: U256,
    /// Access size
    pub size: U256,
    /// Program counter
    pub pc: usize,
    /// Whether access is write
    pub write: bool,
}

/// Memory allocation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryAllocation {
    /// Memory offset
    pub offset: U256,
    /// Allocation size
    pub size: U256,
    /// Program counter
    pub pc: usize,
}

/// Memory analysis results
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemoryAnalysis {
    /// Memory accesses found in code
    pub accesses: Vec<MemoryAccess>,
    /// Memory allocations
    pub allocations: Vec<MemoryAllocation>,
    /// Maximum memory size used
    pub max_size: u64,
    /// Memory safety violations found
    pub violations: Vec<MemoryViolation>,
}

/// Memory safety violation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemoryViolation {
    /// Type of violation
    pub violation_type: MemoryViolationType,
    /// Offset where violation occurred
    pub offset: u64,
    /// Size of access/allocation
    pub size: u64,
    /// Additional context
    pub context: String,
}

/// Type of memory violation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum MemoryViolationType {
    /// Access outside allocated memory
    #[default]
    OutOfBounds,
    /// Overlapping allocations
    Overlap,
    /// Memory size exceeds limit
    SizeLimit,
    /// Use after free
    UseAfterFree,
    /// Double free
    DoubleFree,
}

/// Access control check
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccessControl {
    /// Owner address
    pub owner: H160,
    /// Caller address
    pub caller: H160,
    /// Program counter
    pub pc: usize,
}

/// Constructor call
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Constructor {
    /// Constructor code length
    pub code_length: U256,
    /// Constructor value
    pub value: U256,
    /// Constructor gas
    pub gas: U256,
    /// Constructor caller
    pub caller: H160,
    /// Program counter
    pub pc: usize,
}

/// Memory access
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemoryAccessNew {
    /// Memory offset
    pub offset: U256,
    /// Access size
    pub size: U256,
    /// Program counter
    pub pc: u64,
    /// Write access
    pub write: bool,
}

/// Memory allocation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemoryAllocationNew {
    /// Memory offset
    pub offset: U256,
    /// Allocation size
    pub size: U256,
    /// Program counter
    pub pc: u64,
}

/// State transition
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StateTransition {
    /// Storage slot
    pub slot: H256,
    /// Value
    pub value: U256,
    /// Program counter
    pub pc: u64,
    /// Write access
    pub write: bool,
}

/// Storage access
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageAccessNew {
    /// Storage slot
    pub slot: H256,
    /// Value
    pub value: U256,
    /// Program counter
    pub pc: u64,
    /// Write access
    pub write: bool,
    /// Is initialization
    pub is_init: bool,
}

/// Access control check
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccessControlNew {
    /// Caller address
    pub caller: Address,
    /// Program counter
    pub pc: u64,
}

/// Constructor call
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConstructorNew {
    /// Caller address
    pub caller: Address,
    /// Value sent
    pub value: U256,
    /// Gas limit
    pub gas: U256,
    /// Program counter
    pub pc: u64,
}

/// Memory access
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemoryAccessNewNew {
    /// Memory offset
    pub offset: U256,
    /// Access size
    pub size: U256,
    /// Program counter
    pub pc: u64,
    /// Write access
    pub write: bool,
}

/// Memory allocation
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MemoryAllocationNewNew {
    /// Memory offset
    pub offset: U256,
    /// Allocation size
    pub size: U256,
    /// Program counter
    pub pc: u64,
}

/// State transition
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StateTransitionNew {
    /// Storage slot
    pub slot: H256,
    /// Value
    pub value: U256,
    /// Program counter
    pub pc: u64,
    /// Write access
    pub write: bool,
}

/// Storage access
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageAccessNewNew {
    /// Storage slot
    pub slot: H256,
    /// Value
    pub value: U256,
    /// Program counter
    pub pc: u64,
    /// Write access
    pub write: bool,
    /// Is initialization
    pub is_init: bool,
}

/// Runtime analysis
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeAnalysisNew {
    /// Memory accesses
    pub memory_accesses: Vec<MemoryAccess>,
    /// Memory allocations
    pub memory_allocations: Vec<MemoryAllocation>,
    /// State transitions
    pub state_transitions: Vec<StateTransition>,
    /// Storage accesses
    pub storage_accesses: Vec<StorageAccess>,
    /// Access control checks
    pub access_checks: Vec<AccessControl>,
    /// Constructor calls
    pub constructor_calls: Vec<Constructor>,
}

/// Access control information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessControlNewest {
    /// Owner address
    pub owner: H160,
    /// Caller address
    pub caller: H160,
    /// Program counter
    pub pc: usize,
}

/// Constructor information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstructorNewest {
    /// Constructor code length
    pub code_length: U256,
    /// Constructor value
    pub value: U256,
    /// Constructor gas
    pub gas: U256,
    /// Constructor caller
    pub caller: H160,
    /// Program counter
    pub pc: usize,
}

/// Memory access information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAccessNewest {
    /// Memory offset
    pub offset: U256,
    /// Memory size
    pub size: U256,
    /// Program counter
    pub pc: usize,
    /// Write flag
    pub write: bool,
}

/// Memory allocation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAllocationNewest {
    /// Memory offset
    pub offset: U256,
    /// Memory size
    pub size: U256,
    /// Program counter
    pub pc: usize,
}

/// State transition information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransitionNewest {
    /// Storage slot
    pub slot: H256,
    /// Storage value
    pub value: U256,
    /// Program counter
    pub pc: usize,
    /// Write flag
    pub write: bool,
}

/// Storage access information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageAccessNewest {
    /// Storage slot
    pub slot: H256,
    /// Storage value
    pub value: U256,
    /// Program counter
    pub pc: usize,
    /// Write flag
    pub write: bool,
    /// Initialization flag
    pub is_init: bool,
}

/// Memory violation type
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum MemoryViolationTypeNew {
    /// Access outside allocated memory
    #[default]
    OutOfBounds,
    /// Overlapping allocations
    Overlap,
    /// Size limit exceeded
    SizeLimit,
    /// Use after free
    UseAfterFree,
    /// Double free
    DoubleFree,
}

/// Runtime analysis information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuntimeAnalysisNewest {
    /// Access control information
    pub access_control: Option<AccessControlNewest>,
    /// Constructor information
    pub constructor: Option<ConstructorNewest>,
    /// Memory accesses
    pub memory_accesses: Vec<MemoryAccessNewest>,
    /// Memory allocations
    pub memory_allocations: Vec<MemoryAllocationNewest>,
    /// State transitions
    pub state_transitions: Vec<StateTransitionNewest>,
    /// Storage accesses
    pub storage_accesses: Vec<StorageAccessNewest>,
}
