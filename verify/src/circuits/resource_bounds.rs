use anyhow::Result;
use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_relations::lc;

/// Circuit for verifying resource usage bounds in WebAssembly modules
#[derive(Debug)]
pub struct ResourceBoundsCircuit<F: Field> {
    /// Maximum allowed stack depth
    max_stack_depth: u32,
    /// Maximum allowed call depth
    max_call_depth: u32,
    /// Maximum allowed loop iterations
    max_loop_iterations: u32,
    /// Maximum allowed function table size
    max_table_size: u32,
    /// Current stack depth
    current_stack_depth: u32,
    /// Current call depth 
    current_call_depth: u32,
    /// Current loop iteration count
    current_loop_count: u32,
    /// Current function table size
    current_table_size: u32,
    /// Phantom data for generic type
    _phantom: std::marker::PhantomData<F>,
}

impl<F: Field> ResourceBoundsCircuit<F> {
    /// Create a new resource bounds circuit with specified limits
    pub fn new(
        max_stack_depth: u32,
        max_call_depth: u32,
        max_loop_iterations: u32,
        max_table_size: u32,
    ) -> Self {
        Self {
            max_stack_depth,
            max_call_depth,
            max_loop_iterations,
            max_table_size,
            current_stack_depth: 0,
            current_call_depth: 0,
            current_loop_count: 0,
            current_table_size: 0,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Validate stack depth
    pub fn validate_stack_push(&mut self) -> Result<()> {
        self.current_stack_depth += 1;
        if self.current_stack_depth > self.max_stack_depth {
            return Err(anyhow::anyhow!(
                "Stack depth {} exceeds maximum allowed {}",
                self.current_stack_depth,
                self.max_stack_depth
            ));
        }
        Ok(())
    }

    /// Validate stack pop
    pub fn validate_stack_pop(&mut self) -> Result<()> {
        if self.current_stack_depth == 0 {
            return Err(anyhow::anyhow!("Stack underflow"));
        }
        self.current_stack_depth -= 1;
        Ok(())
    }

    /// Validate function call
    pub fn validate_call(&mut self) -> Result<()> {
        self.current_call_depth += 1;
        if self.current_call_depth > self.max_call_depth {
            return Err(anyhow::anyhow!(
                "Call depth {} exceeds maximum allowed {}",
                self.current_call_depth,
                self.max_call_depth
            ));
        }
        Ok(())
    }

    /// Validate function return
    pub fn validate_return(&mut self) -> Result<()> {
        if self.current_call_depth == 0 {
            return Err(anyhow::anyhow!("Invalid return - not in function"));
        }
        self.current_call_depth -= 1;
        Ok(())
    }

    /// Validate loop iteration
    pub fn validate_loop_iteration(&mut self) -> Result<()> {
        self.current_loop_count += 1;
        if self.current_loop_count > self.max_loop_iterations {
            return Err(anyhow::anyhow!(
                "Loop iterations {} exceeds maximum allowed {}",
                self.current_loop_count,
                self.max_loop_iterations
            ));
        }
        Ok(())
    }

    /// Validate function table size
    pub fn validate_table_size(&mut self, size: u32) -> Result<()> {
        self.current_table_size = size;
        if self.current_table_size > self.max_table_size {
            return Err(anyhow::anyhow!(
                "Table size {} exceeds maximum allowed {}",
                self.current_table_size,
                self.max_table_size
            ));
        }
        Ok(())
    }

    /// Reset loop counter when exiting a loop
    pub fn exit_loop(&mut self) {
        self.current_loop_count = 0;
    }
}

impl<F: Field> ConstraintSynthesizer<F> for ResourceBoundsCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Allocate variables for bounds
        let max_stack_depth_var = cs.new_witness_variable(|| Ok(F::from(self.max_stack_depth as u64)))?;
        let current_stack_depth_var = cs.new_witness_variable(|| Ok(F::from(self.current_stack_depth as u64)))?;
        let max_call_depth_var = cs.new_witness_variable(|| Ok(F::from(self.max_call_depth as u64)))?;
        let current_call_depth_var = cs.new_witness_variable(|| Ok(F::from(self.current_call_depth as u64)))?;
        let max_loop_iterations_var = cs.new_witness_variable(|| Ok(F::from(self.max_loop_iterations as u64)))?;
        let current_loop_count_var = cs.new_witness_variable(|| Ok(F::from(self.current_loop_count as u64)))?;
        let max_table_size_var = cs.new_witness_variable(|| Ok(F::from(self.max_table_size as u64)))?;
        let current_table_size_var = cs.new_witness_variable(|| Ok(F::from(self.current_table_size as u64)))?;

        // Add constraints to ensure bounds are not exceeded
        cs.enforce_constraint(
            lc!() + current_stack_depth_var,
            lc!() + Variable::One,
            lc!() + max_stack_depth_var,
        )?;

        cs.enforce_constraint(
            lc!() + current_call_depth_var,
            lc!() + Variable::One,
            lc!() + max_call_depth_var,
        )?;

        cs.enforce_constraint(
            lc!() + current_loop_count_var,
            lc!() + Variable::One,
            lc!() + max_loop_iterations_var,
        )?;

        cs.enforce_constraint(
            lc!() + current_table_size_var,
            lc!() + Variable::One,
            lc!() + max_table_size_var,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_bounds() -> Result<()> {
        let mut circuit = ResourceBoundsCircuit::<ark_bls12_381::Fr>::new(
            2, // max_stack_depth
            10, // max_call_depth
            100, // max_loop_iterations
            50, // max_table_size
        );

        // Test valid stack operations
        circuit.validate_stack_push()?;
        circuit.validate_stack_push()?;
        circuit.validate_stack_pop()?;
        circuit.validate_stack_pop()?;

        // Test stack overflow
        circuit.validate_stack_push()?;
        circuit.validate_stack_push()?;
        assert!(circuit.validate_stack_push().is_err());

        // Reset stack for underflow test
        circuit.current_stack_depth = 0;
        assert!(circuit.validate_stack_pop().is_err());

        Ok(())
    }

    #[test]
    fn test_call_depth() -> Result<()> {
        let mut circuit = ResourceBoundsCircuit::<ark_bls12_381::Fr>::new(
            10, // max_stack_depth
            2,  // max_call_depth
            100, // max_loop_iterations
            50,  // max_table_size
        );

        // Test valid call depth
        circuit.validate_call()?;
        circuit.validate_call()?;
        circuit.validate_return()?;
        circuit.validate_return()?;

        // Test call depth overflow
        assert!(circuit.validate_call().is_ok());
        assert!(circuit.validate_call().is_ok());
        assert!(circuit.validate_call().is_err());

        Ok(())
    }

    #[test]
    fn test_loop_bounds() -> Result<()> {
        let mut circuit = ResourceBoundsCircuit::<ark_bls12_381::Fr>::new(
            10,  // max_stack_depth
            10,  // max_call_depth
            2,   // max_loop_iterations
            50,  // max_table_size
        );

        // Test valid loop iterations
        circuit.validate_loop_iteration()?;
        circuit.validate_loop_iteration()?;
        
        // Test loop iteration overflow
        assert!(circuit.validate_loop_iteration().is_err());

        // Test loop exit and reset
        circuit.exit_loop();
        assert!(circuit.validate_loop_iteration().is_ok());

        Ok(())
    }

    #[test]
    fn test_table_size() -> Result<()> {
        let mut circuit = ResourceBoundsCircuit::<ark_bls12_381::Fr>::new(
            10,  // max_stack_depth
            10,  // max_call_depth
            100, // max_loop_iterations
            2,   // max_table_size
        );

        // Test valid table sizes
        circuit.validate_table_size(1)?;
        circuit.validate_table_size(2)?;
        
        // Test table size overflow
        assert!(circuit.validate_table_size(3).is_err());

        Ok(())
    }
}
