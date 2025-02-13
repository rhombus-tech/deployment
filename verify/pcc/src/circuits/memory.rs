use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};

/// Circuit for verifying memory safety properties
#[derive(Clone)]
pub struct MemorySafetyCircuit<F: Field> {
    // Memory accesses: (offset, size)
    accesses: Vec<(u64, u64)>,
    // Memory allocations: (address, size)
    allocations: Vec<(u64, u64)>,
    _marker: std::marker::PhantomData<F>,
}

impl<F: Field> MemorySafetyCircuit<F> {
    pub fn new(accesses: Vec<(u64, u64)>, allocations: Vec<(u64, u64)>) -> Self {
        println!("Creating circuit with {} accesses and {} allocations", accesses.len(), allocations.len());
        for (i, (offset, size)) in accesses.iter().enumerate() {
            println!("Access {}: offset={}, size={}", i, offset, size);
        }
        for (i, (addr, size)) in allocations.iter().enumerate() {
            println!("Allocation {}: addr={}, size={}", i, addr, size);
        }
        Self {
            accesses,
            allocations,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F: Field> ConstraintSynthesizer<F> for MemorySafetyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        println!("Generating constraints...");
        
        // For each memory access, we need to ensure it falls within an allocation
        for (i, (access_offset, access_size)) in self.accesses.iter().enumerate() {
            println!("Processing access {}: offset={}, size={}", i, access_offset, access_size);
            
            // Create witnesses for the access bounds
            let access_start = cs.new_witness_variable(|| Ok(F::from(*access_offset)))?;
            let access_end = cs.new_witness_variable(|| Ok(F::from(access_offset + access_size)))?;

            // Create a boolean witness for each allocation check
            for (j, (alloc_addr, alloc_size)) in self.allocations.iter().enumerate() {
                println!("Checking against allocation {}: addr={}, size={}", j, alloc_addr, alloc_size);
                
                let alloc_start = cs.new_witness_variable(|| Ok(F::from(*alloc_addr)))?;
                let alloc_end = cs.new_witness_variable(|| Ok(F::from(alloc_addr + alloc_size)))?;

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
                    let diff = if *alloc_addr + *alloc_size >= *access_offset + *access_size {
                        (*alloc_addr + *alloc_size) - (*access_offset + *access_size)
                    } else {
                        0
                    };
                    println!("end_diff = {}", diff);
                    Ok(F::from(diff))
                })?;

                // Create a public input for whether this access is within bounds
                let in_bounds = cs.new_input_variable(|| {
                    let is_valid = *access_offset >= *alloc_addr && 
                                 (*access_offset + *access_size) <= (*alloc_addr + *alloc_size);
                    println!("in_bounds = {}", is_valid as u32);
                    Ok(F::from(is_valid as u32))
                })?;

                // Enforce start_diff = access_start - alloc_start when in_bounds = 1
                let mut lc1 = LinearCombination::new();
                lc1.extend(vec![(F::one(), access_start), (-F::one(), alloc_start)]);
                let mut lc2 = LinearCombination::new();
                lc2.extend(vec![(F::one(), in_bounds)]);
                let mut lc3 = LinearCombination::new();
                lc3.extend(vec![(F::one(), start_diff)]);
                cs.enforce_constraint(lc1, lc2, lc3)?;

                // Enforce end_diff = alloc_end - access_end when in_bounds = 1
                let mut lc1 = LinearCombination::new();
                lc1.extend(vec![(F::one(), alloc_end), (-F::one(), access_end)]);
                let mut lc2 = LinearCombination::new();
                lc2.extend(vec![(F::one(), in_bounds)]);
                let mut lc3 = LinearCombination::new();
                lc3.extend(vec![(F::one(), end_diff)]);
                cs.enforce_constraint(lc1, lc2, lc3)?;

                // Enforce that in_bounds is boolean
                let mut lc1 = LinearCombination::new();
                lc1.extend(vec![(F::one(), in_bounds)]);
                let mut lc2 = LinearCombination::new();
                lc2.extend(vec![(F::one(), in_bounds)]);
                let mut lc3 = LinearCombination::new();
                lc3.extend(vec![(F::one(), in_bounds)]);
                cs.enforce_constraint(lc1, lc2, lc3)?;

                // At least one allocation must be valid for each access
                let mut lc1 = LinearCombination::new();
                lc1.extend(vec![(F::one(), in_bounds)]);
                let mut lc2 = LinearCombination::new();
                lc2.extend(vec![(F::one(), Variable::One)]);
                let mut lc3 = LinearCombination::new();
                lc3.extend(vec![(F::one(), Variable::One)]);
                cs.enforce_constraint(lc1, lc2, lc3)?;
            }
        }

        println!("Generated {} constraints", cs.num_constraints());
        Ok(())
    }
}
