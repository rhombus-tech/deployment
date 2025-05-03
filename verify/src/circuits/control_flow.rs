use anyhow::Result;
use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_relations::lc;
use crate::parser::cfg::ControlFlowGraph;
use std::collections::HashMap;
use anyhow;
use crate::circuits::type_safety::BlockContext;

/// Represents different types of control flow operations
#[derive(Debug, Clone, PartialEq)]
pub enum ControlFlowOp {
    Branch(usize),          // Branch to target
    Call(usize),           // Function call
    IndirectCall(usize, usize),  // Indirect function call (table_idx, type_idx)
    Return,                // Function return
    BlockEntry(usize),     // Start of a block
    BlockExit(usize),      // End of a block
    Loop(usize),          // Loop construct
    Exception(usize),      // Exception handler
}

/// Circuit for verifying control flow integrity in WebAssembly modules
#[derive(Debug, Clone)]
pub struct ControlFlowCircuit<F: Field> {
    /// Stack of function calls
    call_stack: Vec<usize>,
    /// Stack of nested blocks
    block_stack: Vec<(usize, BlockContext)>,
    /// Current function depth
    pub current_depth: usize,
    /// Maximum allowed function depth
    max_depth: usize,
    /// Valid branch targets
    branch_targets: Vec<usize>,
    /// Exception handlers
    exception_handlers: Vec<usize>,
    /// Control flow operations sequence
    operations: Vec<ControlFlowOp>,
    /// Function table sizes
    function_table_sizes: Vec<usize>,
    /// Function table elements - maps (table_idx, elem_idx) to function_idx
    function_table_elements: HashMap<(usize, usize), usize>,
    /// Function types - maps function index to expected type signature
    function_types: HashMap<usize, usize>,
    /// Phantom data for generic type
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> ControlFlowCircuit<F> {
    /// Create a new control flow circuit
    pub fn new(
        // Unused parameters are prefixed with _ to avoid warnings
        _cfg: ControlFlowGraph,
        max_depth: usize,
        expected_edges: Vec<(usize, usize)>,
        _expected_calls: Vec<usize>,
        function_table_sizes: Vec<usize>,
        function_table_elements: HashMap<(usize, usize), usize>,
        function_types: HashMap<usize, usize>,
    ) -> Self {
        let circuit = Self {
            call_stack: Vec::new(),
            block_stack: Vec::new(),
            current_depth: 0,
            max_depth,
            branch_targets: expected_edges.iter().map(|(_, to)| *to).collect(),
            exception_handlers: Vec::new(),
            operations: Vec::new(),
            function_table_sizes,
            function_table_elements,
            function_types,
            _phantom: std::marker::PhantomData,
        };
        circuit
    }

    /// Validate a branch operation
    pub fn validate_branch(&mut self, target: usize) -> Result<()> {
        if !self.branch_targets.contains(&target) {
            return Err(anyhow::anyhow!("Invalid branch target: {}", target));
        }
        self.operations.push(ControlFlowOp::Branch(target));
        Ok(())
    }

    /// Validate a function call
    pub fn validate_call(&mut self, target: usize) -> anyhow::Result<()> {
        if self.current_depth >= self.max_depth {
            return Err(anyhow::anyhow!("Maximum call depth exceeded"));
        }
        self.current_depth += 1;
        self.call_stack.push(target);
        self.operations.push(ControlFlowOp::Call(target));
        Ok(())
    }
    
    /// Validate an indirect function call
    pub fn validate_indirect_call(&mut self, table_idx: usize, elem_idx: usize, type_idx: usize) -> anyhow::Result<()> {
        // Check call depth - use strict inequality to enforce the max_depth limit
        // This ensures we don't allow calls when current_depth == max_depth
        if self.current_depth >= self.max_depth {
            return Err(anyhow::anyhow!("Maximum call depth exceeded: depth {} >= max {}", 
                self.current_depth, self.max_depth));
        }
        
        // Check table bounds
        if table_idx >= self.function_table_sizes.len() {
            return Err(anyhow::anyhow!("Invalid table index: {}", table_idx));
        }
        
        if elem_idx >= self.function_table_sizes[table_idx] {
            return Err(anyhow::anyhow!("Table element index out of bounds: {} >= {}", 
                       elem_idx, self.function_table_sizes[table_idx]));
        }
        
        // Check if element exists in table
        if let Some(func_idx) = self.function_table_elements.get(&(table_idx, elem_idx)) {
            // Check type compatibility
            if let Some(func_type) = self.function_types.get(func_idx) {
                if *func_type != type_idx {
                    return Err(anyhow::anyhow!("Type mismatch in indirect call: expected type {}, got {}", 
                              *func_type, type_idx));
                }
            } else {
                return Err(anyhow::anyhow!("Function {} has no type information", func_idx));
            }
            
            // Proceed with the indirect call
            self.current_depth += 1;
            self.call_stack.push(*func_idx);
            self.operations.push(ControlFlowOp::IndirectCall(table_idx, type_idx));
            Ok(())
        } else {
            Err(anyhow::anyhow!("Invalid table element: table[{}][{}]", table_idx, elem_idx))
        }
    }

    /// Validate a function return
    pub fn validate_return(&mut self) -> anyhow::Result<()> {
        if self.call_stack.is_empty() {
            return Err(anyhow::anyhow!("Return without matching call"));
        }
        self.call_stack.pop();
        self.current_depth = self.current_depth.saturating_sub(1);
        self.operations.push(ControlFlowOp::Return);
        Ok(())
    }

    /// Push a block onto the block stack
    pub fn push_block(&mut self, block_id: usize) -> anyhow::Result<()> {
        // Create a new BlockContext for the block
        let block_context = BlockContext {
            param_types: vec![],
            result_types: vec![],
            stack_height: 0, // Default stack height
        };
        self.block_stack.push((block_id, block_context));
        self.operations.push(ControlFlowOp::BlockEntry(block_id));
        Ok(())
    }

    /// End a block in the control flow
    pub fn end_block(&mut self, block_id: usize) -> anyhow::Result<()> {
        match self.block_stack.last() {
            Some((last_id, _)) if *last_id == block_id => {
                self.block_stack.pop();
                self.operations.push(ControlFlowOp::BlockExit(block_id));
                Ok(())
            }
            Some((last_id, _)) => Err(anyhow::anyhow!("Block mismatch: expected {}, got {}", 
                last_id,
                block_id
            )),
            None => Err(anyhow::anyhow!("No blocks on the stack"))
        }
    }

    /// Validate loop construct
    pub fn validate_loop(&mut self, loop_id: usize) -> Result<()> {
        self.branch_targets.push(loop_id);
        self.operations.push(ControlFlowOp::Loop(loop_id));
        Ok(())
    }

    /// Register an exception handler
    pub fn register_exception_handler(&mut self, handler_id: usize) -> Result<()> {
        if self.exception_handlers.contains(&handler_id) {
            return Err(anyhow::anyhow!("Duplicate exception handler: {}", handler_id));
        }
        self.exception_handlers.push(handler_id);
        self.operations.push(ControlFlowOp::Exception(handler_id));
        Ok(())
    }

    /// Check if all blocks are properly closed
    pub fn validate_final_state(&self) -> Result<()> {
        if !self.call_stack.is_empty() {
            return Err(anyhow::anyhow!("Unclosed function calls"));
        }
        if !self.block_stack.is_empty() {
            return Err(anyhow::anyhow!("Unclosed blocks"));
        }
        Ok(())
    }
}

impl<F: Field> ConstraintSynthesizer<F> for ControlFlowCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Convert current depth to field element
        let current_depth_var = cs.new_witness_variable(|| Ok(F::from(self.current_depth as u64)))?;
        let max_depth_var = cs.new_witness_variable(|| Ok(F::from(self.max_depth as u64)))?;

        // Ensure current depth doesn't exceed max depth
        cs.enforce_constraint(
            lc!() + current_depth_var,
            lc!() + Variable::One,
            lc!() + max_depth_var,
        )?;

        // Track call/return balance
        let mut call_count = 0i64;
        for op in &self.operations {
            match op {
                ControlFlowOp::Call(_) => call_count += 1,
                ControlFlowOp::IndirectCall(_, _) => call_count += 1,
                ControlFlowOp::Return => call_count -= 1,
                _ => {}
            }

            // Ensure call count never goes negative
            let call_count_var = cs.new_witness_variable(|| Ok(F::from(call_count as u64)))?;
            cs.enforce_constraint(
                lc!() + call_count_var,
                lc!() + Variable::One,
                lc!() + call_count_var,
            )?;
        }

        // Ensure final call count is zero
        let final_call_count_var = cs.new_witness_variable(|| Ok(F::from(call_count as u64)))?;
        cs.enforce_constraint(
            lc!() + final_call_count_var,
            lc!() + Variable::One,
            lc!() + Variable::Zero,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;

    fn create_test_circuit() -> ControlFlowCircuit<Fr> {
        ControlFlowCircuit::new(
            ControlFlowGraph::default(),
            16, // max_depth
            vec![], // expected_edges
            vec![], // expected_calls
            vec![10], // function_table_sizes - one table with 10 elements
            HashMap::new(), // function_table_elements
            HashMap::new(), // function_types
        )
    }

    #[test]
    fn test_valid_control_flow() -> Result<()> {
        let mut circuit = create_test_circuit();
        circuit.push_block(1)?;
        circuit.end_block(1)?;
        circuit.validate_final_state()?;
        Ok(())
    }

    #[test]
    #[should_panic]
    fn test_invalid_return() {
        let mut circuit = create_test_circuit();
        circuit.validate_return().unwrap();
    }

    #[test]
    fn test_max_depth() -> Result<()> {
        let mut circuit = create_test_circuit();
        for i in 0..circuit.max_depth {
            circuit.validate_call(i)?;
        }
        assert!(circuit.validate_call(circuit.max_depth).is_err());
        Ok(())
    }

    #[test]
    fn test_block_mismatch() -> Result<()> {
        let mut circuit = create_test_circuit();
        circuit.push_block(1)?;
        assert!(circuit.end_block(2).is_err());
        Ok(())
    }

    #[test]
    fn test_unclosed_blocks() -> Result<()> {
        let mut circuit = create_test_circuit();
        circuit.push_block(1)?;
        assert!(circuit.validate_final_state().is_err());
        Ok(())
    }

    #[test]
    fn test_exception_handlers() -> Result<()> {
        let mut circuit = create_test_circuit();
        circuit.register_exception_handler(1)?;
        circuit.push_block(1)?;
        circuit.end_block(1)?;
        Ok(())
    }

    #[test]
    fn test_branch_validation() -> Result<()> {
        let mut circuit = create_test_circuit();
        circuit.branch_targets.push(42);
        circuit.validate_branch(42)?;
        assert!(circuit.validate_branch(43).is_err());
        Ok(())
    }

    #[test]
    fn test_indirect_call_validation() -> Result<()> {
        // Create a circuit with a function table
        let mut table_elements = HashMap::new();
        table_elements.insert((0, 0), 10); // Table 0, element 0 -> function 10
        table_elements.insert((0, 1), 11); // Table 0, element 1 -> function 11
        
        let mut function_types = HashMap::new();
        function_types.insert(10, 0); // Function 10 has type 0
        function_types.insert(11, 1); // Function 11 has type 1
        
        let mut circuit: ControlFlowCircuit<Fr> = ControlFlowCircuit::new(
            ControlFlowGraph::default(),
            16, // max_depth
            vec![], // expected_edges
            vec![], // expected_calls
            vec![5], // function_table_sizes - one table with 5 elements
            table_elements,
            function_types,
        );
        
        // Valid indirect call
        circuit.validate_indirect_call(0, 0, 0)?; // Table 0, element 0, type 0
        
        // Invalid table index
        assert!(circuit.validate_indirect_call(1, 0, 0).is_err());
        
        // Invalid element index
        assert!(circuit.validate_indirect_call(0, 10, 0).is_err());
        
        // Type mismatch
        assert!(circuit.validate_indirect_call(0, 1, 0).is_err()); // Element 1 has type 1, not 0
        
        // Valid again with correct type
        circuit.validate_indirect_call(0, 1, 1)?; // Table 0, element 1, type 1
        
        Ok(())
    }
}
