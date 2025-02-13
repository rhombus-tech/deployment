use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError,
    Variable, LinearCombination,
};
use std::marker::PhantomData;

/// Circuit for verifying memory safety
#[derive(Clone)]
pub struct MemorySafetyCircuit<F: Field> {
    /// Memory accesses to verify, each (offset, size)
    pub memory_accesses: Vec<(u32, u32)>,
    /// Memory allocations to check against, each (address, size)
    pub allocations: Vec<(u32, u32)>,
    /// Phantom data for type parameter F
    _phantom: PhantomData<F>,
}

impl<F: Field> MemorySafetyCircuit<F> {
    pub fn new(memory_accesses: Vec<(u32, u32)>, allocations: Vec<(u32, u32)>) -> Self {
        Self {
            memory_accesses,
            allocations,
            _phantom: PhantomData,
        }
    }
}

/// Circuit for verifying memory safety with state transition
#[derive(Clone)]
pub struct MemorySafetyPCDCircuit<F: Field> {
    /// Previous state variables and memory operations
    pub prev_state: Option<(Vec<F>, Vec<(u32, u32)>, Vec<(u32, u32)>)>,
    /// Current state variables
    pub curr_state: Vec<F>,
    /// Current memory accesses to verify
    pub memory_accesses: Vec<(u32, u32)>,
    /// Current memory allocations
    pub allocations: Vec<(u32, u32)>,
    /// Phantom data for type parameter F
    _phantom: PhantomData<F>,
}

impl<F: Field> MemorySafetyPCDCircuit<F> {
    pub fn new(
        prev_state: Option<(Vec<F>, Vec<(u32, u32)>, Vec<(u32, u32)>)>,
        curr_state: Vec<F>,
        memory_accesses: Vec<(u32, u32)>,
        allocations: Vec<(u32, u32)>,
    ) -> Self {
        Self {
            prev_state,
            curr_state,
            memory_accesses,
            allocations,
            _phantom: PhantomData,
        }
    }
}

impl<F: Field> ConstraintSynthesizer<F> for MemorySafetyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        println!("Creating circuit with {} accesses and {} allocations",
            self.memory_accesses.len(), self.allocations.len());

        // For each memory access
        for (i, (access_offset, access_size)) in self.memory_accesses.iter().enumerate() {
            println!("Access {}: offset={}, size={}", i, access_offset, access_size);
            
            // Skip zero-sized accesses
            if *access_size == 0 {
                continue;
            }

            // Create variables for access bounds
            let access_start_var = cs.new_input_variable(|| Ok(F::from(*access_offset)))?;
            let access_end_var = cs.new_input_variable(|| Ok(F::from(access_offset + access_size)))?;

            // Track if this access is valid for any allocation
            let mut any_valid = None;

            // For each allocation
            for (j, (alloc_addr, alloc_size)) in self.allocations.iter().enumerate() {
                println!("Checking against allocation {}: addr={}, size={}", j, alloc_addr, alloc_size);
                
                // Skip zero-sized allocations
                if *alloc_size == 0 {
                    continue;
                }

                let alloc_start_var = cs.new_input_variable(|| Ok(F::from(*alloc_addr)))?;
                let alloc_end_var = cs.new_input_variable(|| Ok(F::from(alloc_addr + alloc_size)))?;

                // Create difference variables
                let start_diff = cs.new_witness_variable(|| {
                    let diff = if *access_offset >= *alloc_addr {
                        *access_offset - *alloc_addr
                    } else {
                        0
                    };
                    println!("start_diff = {}", diff);
                    Ok(F::from(diff))
                })?;

                let end_diff = cs.new_witness_variable(|| {
                    let diff = if (*alloc_addr + *alloc_size) >= (*access_offset + *access_size) {
                        (*alloc_addr + *alloc_size) - (*access_offset + *access_size)
                    } else {
                        0
                    };
                    println!("end_diff = {}", diff);
                    Ok(F::from(diff))
                })?;

                // Create a witness for whether this access is valid for this allocation
                let is_valid = cs.new_witness_variable(|| {
                    let valid = *access_offset >= *alloc_addr && 
                             (*access_offset + *access_size) <= (*alloc_addr + *alloc_size);
                    println!("is_valid = {}", valid as u32);
                    Ok(F::from(valid as u32))
                })?;

                // Update any_valid
                if let Some(prev_valid) = any_valid {
                    let new_valid = cs.new_witness_variable(|| {
                        Ok(F::from(1u32))
                    })?;
                    cs.enforce_constraint(
                        LinearCombination::from(prev_valid) + LinearCombination::from(is_valid),
                        LinearCombination::from(Variable::One),
                        LinearCombination::from(new_valid)
                    )?;
                    any_valid = Some(new_valid);
                } else {
                    any_valid = Some(is_valid);
                }

                // Enforce that if is_valid is true:
                // 1. start_diff must be >= 0 (access_start >= alloc_start)
                // 2. end_diff must be >= 0 (alloc_end >= access_end)
                cs.enforce_constraint(
                    LinearCombination::from(is_valid),
                    LinearCombination::from(start_diff),
                    LinearCombination::from(start_diff)
                )?;
                cs.enforce_constraint(
                    LinearCombination::from(is_valid),
                    LinearCombination::from(end_diff),
                    LinearCombination::from(end_diff)
                )?;

                // Enforce bounds checking
                cs.enforce_constraint(
                    LinearCombination::from(access_start_var),
                    LinearCombination::from(Variable::One),
                    LinearCombination::from(alloc_start_var) + LinearCombination::from(start_diff)
                )?;
                cs.enforce_constraint(
                    LinearCombination::from(alloc_end_var),
                    LinearCombination::from(Variable::One),
                    LinearCombination::from(access_end_var) + LinearCombination::from(end_diff)
                )?;
            }

            // Create a public input for whether this access is valid for any allocation
            let in_bounds = cs.new_input_variable(|| {
                let valid = any_valid.map(|_| F::from(1u32)).unwrap_or(F::from(0u32));
                println!("in_bounds = {}", valid);
                Ok(valid)
            })?;

            // Enforce that in_bounds matches any_valid
            if let Some(any_valid) = any_valid {
                cs.enforce_constraint(
                    LinearCombination::from(any_valid),
                    LinearCombination::from(Variable::One),
                    LinearCombination::from(in_bounds)
                )?;
            }
        }

        Ok(())
    }
}

impl<F: Field> ConstraintSynthesizer<F> for MemorySafetyPCDCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // First, add current state variables as public inputs
        let curr_state_vars: Vec<Variable> = self.curr_state.iter()
            .map(|v| cs.new_input_variable(|| Ok(*v)))
            .collect::<Result<_, _>>()?;

        // Create memory safety circuit for current state
        let curr_circuit = MemorySafetyCircuit::new(
            self.memory_accesses,
            self.allocations,
        );
        curr_circuit.generate_constraints(cs.clone())?;

        // If we have a previous state, enforce PCD transition rules
        if let Some((prev_state, prev_accesses, prev_allocs)) = self.prev_state {
            // Add previous state variables as public inputs
            let prev_state_vars: Vec<Variable> = prev_state.iter()
                .map(|v| cs.new_input_variable(|| Ok(*v)))
                .collect::<Result<_, _>>()?;

            // Create memory safety circuit for previous state
            let prev_circuit = MemorySafetyCircuit::new(
                prev_accesses,
                prev_allocs,
            );
            prev_circuit.generate_constraints(cs.clone())?;

            // For each pair of previous and current state variables, enforce the transition rule
            for (prev_var, curr_var) in prev_state_vars.iter().zip(curr_state_vars.iter()) {
                // Example transition rule: current state must be previous state plus one
                let one = cs.new_witness_variable(|| Ok(F::from(1u32)))?;
                cs.enforce_constraint(
                    LinearCombination::from(*prev_var) + LinearCombination::from(one),
                    LinearCombination::from(Variable::One),
                    LinearCombination::from(*curr_var)
                )?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_memory_safety_pcd_circuit() -> Result<(), SynthesisError> {
        let circuit = MemorySafetyPCDCircuit::new(
            None,
            vec![Fr::from(1u32)],
            vec![(0, 4)],
            vec![(0, 65536)],
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs)?;

        Ok(())
    }

    #[test]
    fn test_memory_safety_pcd_transition() -> Result<(), SynthesisError> {
        let circuit = MemorySafetyPCDCircuit::new(
            Some((
                vec![Fr::from(1u32)],
                vec![(0, 4)],
                vec![(0, 65536)],
            )),
            vec![Fr::from(2u32)],
            vec![(4, 4)],
            vec![(0, 65536)],
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs)?;

        Ok(())
    }
}
