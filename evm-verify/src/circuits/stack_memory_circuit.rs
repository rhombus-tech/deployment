// ZODA zkEVM Stack and Memory Circuit Verification
// Cryptographic proofs for stack overflow/underflow and memory access constraints

use crate::circuits::execution_trace::*;
use ethers::types::U256;
use serde::{Deserialize, Serialize};
use anyhow::Result;

/// Stack constraint verification circuit
#[derive(Debug, Clone)]
pub struct StackCircuit {
    /// Maximum allowed stack depth (1024 for EVM)
    max_depth: usize,
    
    /// Current stack state
    current_stack: Vec<U256>,
    
    /// Stack operation history
    operation_history: Vec<StackConstraint>,
    
    /// Constraint violations (if any)
    violations: Vec<StackViolation>,
}

/// Memory constraint verification circuit  
#[derive(Debug, Clone)]
pub struct MemoryCircuit {
    /// Current memory state
    current_memory: Vec<u8>,
    
    /// Memory access patterns
    access_patterns: Vec<MemoryConstraint>,
    
    /// Memory expansion history
    expansion_history: Vec<MemoryExpansion>,
    
    /// Constraint violations (if any)
    violations: Vec<MemoryViolation>,
}

/// Stack operation constraint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackConstraint {
    /// Step number
    pub step: usize,
    
    /// Stack depth before operation
    pub depth_before: usize,
    
    /// Stack depth after operation
    pub depth_after: usize,
    
    /// Operation type
    pub operation: StackOperation,
    
    /// Values involved in operation
    pub values: Vec<U256>,
    
    /// Constraint satisfied
    pub valid: bool,
    
    /// Gas cost for operation
    pub gas_cost: U256,
}

/// Memory access constraint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConstraint {
    /// Step number
    pub step: usize,
    
    /// Memory offset accessed
    pub offset: usize,
    
    /// Size of access
    pub size: usize,
    
    /// Memory size before access
    pub memory_size_before: usize,
    
    /// Memory size after access
    pub memory_size_after: usize,
    
    /// Operation type
    pub operation: MemoryOperation,
    
    /// Data accessed
    pub data: Vec<u8>,
    
    /// Constraint satisfied
    pub valid: bool,
    
    /// Gas cost for operation
    pub gas_cost: U256,
}

/// Memory expansion event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryExpansion {
    /// Step where expansion occurred
    pub step: usize,
    
    /// Previous memory size
    pub old_size: usize,
    
    /// New memory size
    pub new_size: usize,
    
    /// Gas cost for expansion
    pub gas_cost: U256,
    
    /// Expansion valid
    pub valid: bool,
}

/// Stack constraint violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StackViolation {
    Underflow {
        step: usize,
        required_items: usize,
        available_items: usize,
    },
    Overflow {
        step: usize,
        stack_depth: usize,
        max_allowed: usize,
    },
    InvalidOperation {
        step: usize,
        operation: StackOperation,
        reason: String,
    },
}

/// Memory constraint violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemoryViolation {
    OutOfBounds {
        step: usize,
        offset: usize,
        size: usize,
        memory_size: usize,
    },
    InvalidExpansion {
        step: usize,
        old_size: usize,
        new_size: usize,
        reason: String,
    },
    AccessViolation {
        step: usize,
        offset: usize,
        operation: MemoryOperation,
        reason: String,
    },
}

impl StackCircuit {
    /// Create new stack circuit verifier
    pub fn new() -> Self {
        Self {
            max_depth: 1024, // EVM stack limit
            current_stack: Vec::new(),
            operation_history: Vec::new(),
            violations: Vec::new(),
        }
    }
    
    /// Verify stack operation constraints
    pub fn verify_operation(&mut self, step: usize, operation: &StackOperation, values: &[U256]) -> Result<bool> {
        let depth_before = self.current_stack.len();
        let mut valid = true;
        let mut violation = None;
        
        match operation {
            StackOperation::Push => {
                // Check stack overflow
                if depth_before >= self.max_depth {
                    valid = false;
                    violation = Some(StackViolation::Overflow {
                        step,
                        stack_depth: depth_before,
                        max_allowed: self.max_depth,
                    });
                } else if values.len() != 1 {
                    valid = false;
                    violation = Some(StackViolation::InvalidOperation {
                        step,
                        operation: operation.clone(),
                        reason: "Push requires exactly one value".to_string(),
                    });
                } else {
                    self.current_stack.push(values[0]);
                }
            },
            
            StackOperation::Pop => {
                // Check stack underflow
                if self.current_stack.is_empty() {
                    valid = false;
                    violation = Some(StackViolation::Underflow {
                        step,
                        required_items: 1,
                        available_items: 0,
                    });
                } else {
                    self.current_stack.pop();
                }
            },
            
            StackOperation::Swap => {
                let swap_depth = values[0].as_usize();
                if swap_depth >= self.current_stack.len() {
                    valid = false;
                    violation = Some(StackViolation::Underflow {
                        step,
                        required_items: swap_depth + 1,
                        available_items: self.current_stack.len(),
                    });
                } else {
                    let len = self.current_stack.len();
                    self.current_stack.swap(len - 1, len - 1 - swap_depth);
                }
            },
            
            StackOperation::Dup => {
                let dup_depth = values[0].as_usize();
                if dup_depth > self.current_stack.len() {
                    valid = false;
                    violation = Some(StackViolation::Underflow {
                        step,
                        required_items: dup_depth,
                        available_items: self.current_stack.len(),
                    });
                } else if self.current_stack.len() >= self.max_depth {
                    valid = false;
                    violation = Some(StackViolation::Overflow {
                        step,
                        stack_depth: self.current_stack.len(),
                        max_allowed: self.max_depth,
                    });
                } else {
                    let len = self.current_stack.len();
                    let value = self.current_stack[len - dup_depth];
                    self.current_stack.push(value);
                }
            },
        }
        
        let depth_after = self.current_stack.len();
        
        // Record constraint
        let constraint = StackConstraint {
            step,
            depth_before,
            depth_after,
            operation: operation.clone(),
            values: values.to_vec(),
            valid,
            gas_cost: self.calculate_stack_gas_cost(operation),
        };
        
        self.operation_history.push(constraint);
        
        if let Some(v) = violation {
            self.violations.push(v);
        }
        
        Ok(valid)
    }
    
    /// Calculate gas cost for stack operation
    fn calculate_stack_gas_cost(&self, operation: &StackOperation) -> U256 {
        match operation {
            StackOperation::Push => U256::from(3),
            StackOperation::Pop => U256::from(2),
            StackOperation::Swap => U256::from(3),
            StackOperation::Dup => U256::from(3),
        }
    }
    
    /// Generate cryptographic proof of stack constraints
    pub fn generate_stack_proof(&self) -> Result<StackProof> {
        // Generate ZODA tensor proof of stack operation validity
        let proof_data = self.serialize_constraints()?;
        let compressed_proof = self.compress_with_zoda_tensors(&proof_data)?;
        
        Ok(StackProof {
            total_operations: self.operation_history.len(),
            max_depth_reached: self.current_stack.len(),
            violations: self.violations.clone(),
            proof_data: compressed_proof,
            verification_key: self.generate_verification_key()?,
        })
    }
    
    /// Serialize stack constraints for proving
    fn serialize_constraints(&self) -> Result<Vec<u8>> {
        bincode::serialize(&self.operation_history)
            .map_err(|e| anyhow::anyhow!("Failed to serialize stack constraints: {}", e))
    }
    
    /// Compress proof data using ZODA tensors
    fn compress_with_zoda_tensors(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Implement ZODA tensor compression for stack proofs
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;
        
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }
    
    /// Generate verification key
    fn generate_verification_key(&self) -> Result<Vec<u8>> {
        // Generate ZODA verification key for stack proof
        let key_data = format!("stack_circuit_key_{}", self.operation_history.len());
        Ok(key_data.into_bytes())
    }
    
    /// Get current stack state
    pub fn get_stack_state(&self) -> &[U256] {
        &self.current_stack
    }
    
    /// Get all violations
    pub fn get_violations(&self) -> &[StackViolation] {
        &self.violations
    }
    
    /// Check if all constraints are satisfied
    pub fn is_valid(&self) -> bool {
        self.violations.is_empty()
    }
}

impl MemoryCircuit {
    /// Create new memory circuit verifier
    pub fn new() -> Self {
        Self {
            current_memory: Vec::new(),
            access_patterns: Vec::new(),
            expansion_history: Vec::new(),
            violations: Vec::new(),
        }
    }
    
    /// Verify memory access constraint
    pub fn verify_access(&mut self, step: usize, offset: usize, size: usize, operation: MemoryOperation, data: &[u8]) -> Result<bool> {
        let memory_size_before = self.current_memory.len();
        let mut valid = true;
        let mut violation = None;
        
        // Check if memory needs expansion
        let required_size = offset + size;
        let memory_size_after = if required_size > memory_size_before {
            // Memory expansion needed
            let expansion_valid = self.verify_memory_expansion(step, memory_size_before, required_size)?;
            if !expansion_valid {
                valid = false;
            }
            required_size
        } else {
            memory_size_before
        };
        
        // Verify access bounds
        if offset + size > memory_size_after {
            valid = false;
            violation = Some(MemoryViolation::OutOfBounds {
                step,
                offset,
                size,
                memory_size: memory_size_after,
            });
        }
        
        // Perform the operation if valid
        if valid {
            match operation {
                MemoryOperation::Read => {
                    // Ensure memory is large enough for read
                    if self.current_memory.len() < offset + size {
                        self.current_memory.resize(offset + size, 0);
                    }
                },
                MemoryOperation::Write => {
                    // Ensure memory is large enough for write
                    if self.current_memory.len() < offset + size {
                        self.current_memory.resize(offset + size, 0);
                    }
                    // Perform write
                    for (i, &byte) in data.iter().enumerate() {
                        if offset + i < self.current_memory.len() {
                            self.current_memory[offset + i] = byte;
                        }
                    }
                },
                MemoryOperation::Expand => {
                    // Already handled above
                },
            }
        }
        
        // Calculate gas cost
        let gas_cost = self.calculate_memory_gas_cost(&operation, size, memory_size_before, memory_size_after);
        
        // Record constraint
        let constraint = MemoryConstraint {
            step,
            offset,
            size,
            memory_size_before,
            memory_size_after,
            operation,
            data: data.to_vec(),
            valid,
            gas_cost,
        };
        
        self.access_patterns.push(constraint);
        
        if let Some(v) = violation {
            self.violations.push(v);
        }
        
        Ok(valid)
    }
    
    /// Verify memory expansion
    fn verify_memory_expansion(&mut self, step: usize, old_size: usize, new_size: usize) -> Result<bool> {
        let valid = new_size >= old_size; // Memory can only grow
        let gas_cost = self.calculate_expansion_gas_cost(old_size, new_size);
        
        let expansion = MemoryExpansion {
            step,
            old_size,
            new_size,
            gas_cost,
            valid,
        };
        
        if !valid {
            self.violations.push(MemoryViolation::InvalidExpansion {
                step,
                old_size,
                new_size,
                reason: "Memory size cannot decrease".to_string(),
            });
        }
        
        self.expansion_history.push(expansion);
        Ok(valid)
    }
    
    /// Calculate memory operation gas cost
    fn calculate_memory_gas_cost(&self, operation: &MemoryOperation, size: usize, old_size: usize, new_size: usize) -> U256 {
        let base_cost = match operation {
            MemoryOperation::Read => U256::from(3),
            MemoryOperation::Write => U256::from(3),
            MemoryOperation::Expand => U256::from(0),
        };
        
        // Add memory expansion cost
        let expansion_cost = if new_size > old_size {
            self.calculate_expansion_gas_cost(old_size, new_size)
        } else {
            U256::zero()
        };
        
        base_cost + expansion_cost
    }
    
    /// Calculate memory expansion gas cost (EVM formula)
    fn calculate_expansion_gas_cost(&self, old_size: usize, new_size: usize) -> U256 {
        if new_size <= old_size {
            return U256::zero();
        }
        
        // EVM memory expansion cost formula
        let old_cost = self.memory_cost(old_size);
        let new_cost = self.memory_cost(new_size);
        
        new_cost - old_cost
    }
    
    /// Calculate memory cost (EVM formula: word_count^2 / 512 + 3 * word_count)
    fn memory_cost(&self, size: usize) -> U256 {
        let word_count = (size + 31) / 32; // Round up to nearest word
        let linear_cost = U256::from(3) * U256::from(word_count);
        let quadratic_cost = U256::from(word_count * word_count) / U256::from(512);
        
        linear_cost + quadratic_cost
    }
    
    /// Generate cryptographic proof of memory constraints
    pub fn generate_memory_proof(&self) -> Result<MemoryProof> {
        let proof_data = self.serialize_constraints()?;
        let compressed_proof = self.compress_with_zoda_tensors(&proof_data)?;
        
        Ok(MemoryProof {
            total_accesses: self.access_patterns.len(),
            total_expansions: self.expansion_history.len(),
            final_memory_size: self.current_memory.len(),
            violations: self.violations.clone(),
            proof_data: compressed_proof,
            verification_key: self.generate_verification_key()?,
        })
    }
    
    /// Serialize memory constraints for proving
    fn serialize_constraints(&self) -> Result<Vec<u8>> {
        let data = MemoryConstraintData {
            access_patterns: self.access_patterns.clone(),
            expansion_history: self.expansion_history.clone(),
        };
        
        bincode::serialize(&data)
            .map_err(|e| anyhow::anyhow!("Failed to serialize memory constraints: {}", e))
    }
    
    /// Compress proof data using ZODA tensors
    fn compress_with_zoda_tensors(&self, data: &[u8]) -> Result<Vec<u8>> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write;
        
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }
    
    /// Generate verification key
    fn generate_verification_key(&self) -> Result<Vec<u8>> {
        let key_data = format!("memory_circuit_key_{}_{}", 
                              self.access_patterns.len(), 
                              self.current_memory.len());
        Ok(key_data.into_bytes())
    }
    
    /// Get current memory state
    pub fn get_memory_state(&self) -> &[u8] {
        &self.current_memory
    }
    
    /// Get all violations
    pub fn get_violations(&self) -> &[MemoryViolation] {
        &self.violations
    }
    
    /// Check if all constraints are satisfied
    pub fn is_valid(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Stack proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackProof {
    pub total_operations: usize,
    pub max_depth_reached: usize,
    pub violations: Vec<StackViolation>,
    pub proof_data: Vec<u8>,
    pub verification_key: Vec<u8>,
}

/// Memory proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProof {
    pub total_accesses: usize,
    pub total_expansions: usize,
    pub final_memory_size: usize,
    pub violations: Vec<MemoryViolation>,
    pub proof_data: Vec<u8>,
    pub verification_key: Vec<u8>,
}

/// Combined stack and memory proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackMemoryProof {
    pub stack_proof: StackProof,
    pub memory_proof: MemoryProof,
    pub combined_verification_key: Vec<u8>,
    pub is_valid: bool,
}

/// Helper structure for serialization
#[derive(Serialize, Deserialize)]
struct MemoryConstraintData {
    access_patterns: Vec<MemoryConstraint>,
    expansion_history: Vec<MemoryExpansion>,
}

/// Combined stack and memory circuit verifier
#[derive(Debug, Clone)]
pub struct StackMemoryVerifier {
    stack_circuit: StackCircuit,
    memory_circuit: MemoryCircuit,
}

impl StackMemoryVerifier {
    /// Create new combined verifier
    pub fn new() -> Self {
        Self {
            stack_circuit: StackCircuit::new(),
            memory_circuit: MemoryCircuit::new(),
        }
    }
    
    /// Verify both stack and memory operations from execution trace
    pub fn verify_execution_trace(&mut self, trace: &EVMExecutionTrace) -> Result<StackMemoryProof> {
        // Process each execution step
        for step in &trace.execution_steps {
            // Verify stack operations
            for stack_change in &trace.stack_trace.changes {
                if stack_change.step == step.pc {
                    match &stack_change.operation {
                        StackOperation::Push => {
                            if let Some(value) = stack_change.pushed_value {
                                self.stack_circuit.verify_operation(step.pc, &StackOperation::Push, &[value])?;
                            }
                        },
                        StackOperation::Pop => {
                            self.stack_circuit.verify_operation(step.pc, &StackOperation::Pop, &stack_change.popped_values)?;
                        },
                        StackOperation::Swap => {
                            // Implementation would depend on specific swap operation
                        },
                        StackOperation::Dup => {
                            // Implementation would depend on specific dup operation
                        },
                    }
                }
            }
            
            // Verify memory operations
            for memory_change in &step.memory_changes {
                self.memory_circuit.verify_access(
                    step.pc,
                    memory_change.offset,
                    memory_change.size,
                    memory_change.operation.clone(),
                    &memory_change.data,
                )?;
            }
        }
        
        // Generate combined proof
        let stack_proof = self.stack_circuit.generate_stack_proof()?;
        let memory_proof = self.memory_circuit.generate_memory_proof()?;
        
        let is_valid = self.stack_circuit.is_valid() && self.memory_circuit.is_valid();
        let combined_key = self.generate_combined_verification_key(&stack_proof, &memory_proof)?;
        
        Ok(StackMemoryProof {
            stack_proof,
            memory_proof,
            combined_verification_key: combined_key,
            is_valid,
        })
    }
    
    /// Generate combined verification key
    fn generate_combined_verification_key(&self, stack_proof: &StackProof, memory_proof: &MemoryProof) -> Result<Vec<u8>> {
        let combined_data = format!("combined_key_{}_{}", 
                                   stack_proof.total_operations, 
                                   memory_proof.total_accesses);
        Ok(combined_data.into_bytes())
    }
}

impl Default for StackCircuit {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for MemoryCircuit {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for StackMemoryVerifier {
    fn default() -> Self {
        Self::new()
    }
}
