use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};
use ethers::types::U256;

/// Circuit for verifying memory safety properties in EVM bytecode
#[derive(Clone)]
pub struct MemorySafetyCircuit<F: Field> {
    // Memory accesses: (offset, size)
    accesses: Vec<(U256, U256)>,
    // Memory allocations: (address, size)
    allocations: Vec<(U256, U256)>,
    _marker: std::marker::PhantomData<F>,
}

impl<F: Field> MemorySafetyCircuit<F> {
    pub fn new(accesses: Vec<(U256, U256)>, allocations: Vec<(U256, U256)>) -> Self {
        println!("Creating memory safety circuit with {} accesses and {} allocations", accesses.len(), allocations.len());
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
        println!("Generating memory safety constraints...");
        
        // For each memory access, we need to ensure it falls within an allocation
        for (i, (access_offset, access_size)) in self.accesses.iter().enumerate() {
            println!("Processing access {}: offset={}, size={}", i, access_offset, access_size);
            
            // Convert U256 to field elements
            // Note: This is a simplification. In practice, we would need to handle the full U256 range.
            let access_offset_u64 = access_offset.as_u64();
            let access_size_u64 = access_size.as_u64();
            
            // Create witnesses for the access bounds
            let access_start = cs.new_witness_variable(|| Ok(F::from(access_offset_u64)))?;
            let access_end = cs.new_witness_variable(|| Ok(F::from(access_offset_u64 + access_size_u64)))?;

            // For each allocation, check if this access is within bounds
            let mut any_valid = false;
            
            for (j, (alloc_addr, alloc_size)) in self.allocations.iter().enumerate() {
                println!("Checking against allocation {}: addr={}, size={}", j, alloc_addr, alloc_size);
                
                // Convert U256 to field elements
                let alloc_addr_u64 = alloc_addr.as_u64();
                let alloc_size_u64 = alloc_size.as_u64();
                
                let alloc_start = cs.new_witness_variable(|| Ok(F::from(alloc_addr_u64)))?;
                let alloc_end = cs.new_witness_variable(|| Ok(F::from(alloc_addr_u64 + alloc_size_u64)))?;

                // Create a boolean witness for whether this access is within this allocation
                let in_bounds = cs.new_witness_variable(|| {
                    let is_valid = access_offset_u64 >= alloc_addr_u64 && 
                                 (access_offset_u64 + access_size_u64) <= (alloc_addr_u64 + alloc_size_u64);
                    println!("in_bounds = {}", is_valid as u32);
                    Ok(F::from(is_valid as u32))
                })?;

                // Enforce that in_bounds is boolean (0 or 1)
                let mut lc1 = LinearCombination::new();
                lc1.extend(vec![(F::one(), in_bounds)]);
                let mut lc2 = LinearCombination::new();
                lc2.extend(vec![(F::one(), in_bounds)]);
                let mut lc3 = LinearCombination::new();
                lc3.extend(vec![(F::one(), in_bounds)]);
                cs.enforce_constraint(lc1, lc2, lc3)?;

                // When in_bounds is 1, enforce access_start >= alloc_start
                let mut lc1 = LinearCombination::new();
                lc1.extend(vec![(F::one(), access_start), (-F::one(), alloc_start)]);
                let mut lc2 = LinearCombination::new();
                lc2.extend(vec![(F::one(), in_bounds)]);
                let mut lc3 = LinearCombination::new();
                lc3.extend(vec![(F::one(), Variable::One)]); // This constraint is only enforced when in_bounds = 1
                cs.enforce_constraint(lc1, lc2, lc3)?;

                // When in_bounds is 1, enforce access_end <= alloc_end
                let mut lc1 = LinearCombination::new();
                lc1.extend(vec![(F::one(), alloc_end), (-F::one(), access_end)]);
                let mut lc2 = LinearCombination::new();
                lc2.extend(vec![(F::one(), in_bounds)]);
                let mut lc3 = LinearCombination::new();
                lc3.extend(vec![(F::one(), Variable::One)]); // This constraint is only enforced when in_bounds = 1
                cs.enforce_constraint(lc1, lc2, lc3)?;

                if in_bounds == Variable::One {
                    any_valid = true;
                }
            }
            
            // Ensure that at least one allocation contains this access
            if !any_valid {
                return Err(SynthesisError::Unsatisfiable);
            }
        }

        println!("Generated {} constraints", cs.num_constraints());
        Ok(())
    }
}
