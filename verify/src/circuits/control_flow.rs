use anyhow::Result;
use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_relations::lc;
use crate::parser::cfg::ControlFlowGraph;
use ark_bls12_381::Fr;

/// Represents different types of control flow operations
#[derive(Debug, Clone, PartialEq)]
pub enum ControlFlowOp {
    Branch(usize),          // Branch to target
    Call(usize),           // Function call
    Return,                // Function return
    BlockStart(usize),     // Start of a block
    BlockEnd(usize),       // End of a block
    Loop(usize),          // Loop construct
    Exception(usize),      // Exception handler
}

/// Circuit for verifying control flow integrity in WebAssembly modules
#[derive(Debug)]
pub struct ControlFlowCircuit<F: Field> {
    /// Stack of function calls
    call_stack: Vec<usize>,
    /// Stack of nested blocks
    block_stack: Vec<usize>,
    /// Current function depth
    current_depth: usize,
    /// Maximum allowed function depth
    max_depth: usize,
    /// Valid branch targets
    branch_targets: Vec<usize>,
    /// Exception handlers
    exception_handlers: Vec<usize>,
    /// Control flow operations sequence
    operations: Vec<ControlFlowOp>,
    /// Phantom data for generic type
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> ControlFlowCircuit<F> {
    /// Create a new control flow circuit
    pub fn new(
        cfg: ControlFlowGraph,
        max_depth: usize,
        expected_edges: Vec<(usize, usize)>,
        expected_calls: Vec<usize>,
    ) -> Self {
        Self {
            call_stack: Vec::new(),
            block_stack: Vec::new(),
            current_depth: 0,
            max_depth,
            branch_targets: expected_edges.iter().map(|(_, to)| *to).collect(),
            exception_handlers: Vec::new(),
            operations: Vec::new(),
            _phantom: std::marker::PhantomData,
        }
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
    pub fn validate_call(&mut self, target: usize) -> Result<()> {
        if self.current_depth >= self.max_depth {
            return Err(anyhow::anyhow!("Maximum call depth exceeded"));
        }
        self.current_depth += 1;
        self.call_stack.push(target);
        self.operations.push(ControlFlowOp::Call(target));
        Ok(())
    }

    /// Validate a function return
    pub fn validate_return(&mut self) -> Result<()> {
        if self.call_stack.is_empty() {
            return Err(anyhow::anyhow!("Return without matching call"));
        }
        self.call_stack.pop();
        self.current_depth = self.current_depth.saturating_sub(1);
        self.operations.push(ControlFlowOp::Return);
        Ok(())
    }

    /// Validate block start
    pub fn validate_block_start(&mut self, block_id: usize) -> Result<()> {
        self.block_stack.push(block_id);
        self.operations.push(ControlFlowOp::BlockStart(block_id));
        Ok(())
    }

    /// Validate block end
    pub fn validate_block_end(&mut self, block_id: usize) -> Result<()> {
        match self.block_stack.last() {
            Some(&last_block) if last_block == block_id => {
                self.block_stack.pop();
                self.operations.push(ControlFlowOp::BlockEnd(block_id));
                Ok(())
            }
            Some(&last_block) => Err(anyhow::anyhow!(
                "Mismatched block end. Expected {}, got {}",
                last_block,
                block_id
            )),
            None => Err(anyhow::anyhow!("No matching block start")),
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

    fn create_test_circuit() -> ControlFlowCircuit<Fr> {
        ControlFlowCircuit::new(
            ControlFlowGraph::default(),
            16, // max_depth
            vec![], // expected_edges
            vec![], // expected_calls
        )
    }

    #[test]
    fn test_valid_control_flow() -> Result<()> {
        let mut circuit = create_test_circuit();
        circuit.validate_block_start(1)?;
        circuit.validate_block_end(1)?;
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
        circuit.validate_block_start(1)?;
        assert!(circuit.validate_block_end(2).is_err());
        Ok(())
    }

    #[test]
    fn test_unclosed_blocks() -> Result<()> {
        let mut circuit = create_test_circuit();
        circuit.validate_block_start(1)?;
        assert!(circuit.validate_final_state().is_err());
        Ok(())
    }

    #[test]
    fn test_exception_handlers() -> Result<()> {
        let mut circuit = create_test_circuit();
        circuit.register_exception_handler(1)?;
        circuit.validate_block_start(1)?;
        circuit.validate_block_end(1)?;
        Ok(())
    }

    #[test]
    fn test_branch_validation() -> Result<()> {
        let mut circuit = create_test_circuit();
        circuit.branch_targets.push(1);
        circuit.validate_branch(1)?;
        assert!(circuit.validate_branch(2).is_err());
        Ok(())
    }
}
