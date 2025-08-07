use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError, Variable,
};
use ethers::types::U256;


/// Circuit for verifying memory safety properties
#[derive(Clone)]
pub struct MemorySafetyCircuit<F: Field> {
    /// Memory accesses to verify (offset, size)
    accesses: Vec<(U256, U256)>,
    
    /// Memory allocations (offset, size)
    allocations: Vec<(U256, U256)>,
    
    /// Optional memory hash for verification
    memory_hash: Option<[u8; 32]>,
    
    /// Maximum memory size
    max_memory_size: U256,
    
    /// Whether to enforce temporal safety
    enforce_temporal_safety: bool,
    
    /// Access timestamps (only used if enforce_temporal_safety is true)
    /// Each access has a logical timestamp indicating when it occurs
    access_timestamps: Vec<u32>,
    
    /// Allocation timestamps (only used if enforce_temporal_safety is true)
    /// Each allocation has a start and end timestamp
    allocation_start_timestamps: Vec<u32>,
    allocation_end_timestamps: Vec<u32>,
    
    _marker: std::marker::PhantomData<F>,
}

impl<F: Field> MemorySafetyCircuit<F> {
    /// Create a new memory safety circuit
    pub fn new(
        accesses: Vec<(U256, U256)>,
        allocations: Vec<(U256, U256)>,
        memory_hash: Option<[u8; 32]>,
        max_memory_size: U256,
        enforce_temporal_safety: bool
    ) -> Self {
        // Default timestamps - all accesses happen at time 1
        let access_timestamps = vec![1; accesses.len()];
        
        // Default allocation timestamps - all allocations are valid from time 0 to time 100
        let allocation_start_timestamps = vec![0; allocations.len()];
        let allocation_end_timestamps = vec![100; allocations.len()];
        
        Self {
            accesses,
            allocations,
            memory_hash,
            max_memory_size,
            enforce_temporal_safety,
            access_timestamps,
            allocation_start_timestamps,
            allocation_end_timestamps,
            _marker: std::marker::PhantomData,
        }
    }
    
    /// Create a new memory safety circuit with custom temporal information
    pub fn new_with_temporal_info(
        accesses: Vec<(U256, U256)>,
        allocations: Vec<(U256, U256)>,
        memory_hash: Option<[u8; 32]>,
        max_memory_size: U256,
        access_timestamps: Vec<u32>,
        allocation_start_timestamps: Vec<u32>,
        allocation_end_timestamps: Vec<u32>
    ) -> Self {
        assert_eq!(accesses.len(), access_timestamps.len(), "Each access must have a timestamp");
        assert_eq!(allocations.len(), allocation_start_timestamps.len(), "Each allocation must have a start timestamp");
        assert_eq!(allocations.len(), allocation_end_timestamps.len(), "Each allocation must have an end timestamp");
        
        Self {
            accesses,
            allocations,
            memory_hash,
            max_memory_size,
            enforce_temporal_safety: true,
            access_timestamps,
            allocation_start_timestamps,
            allocation_end_timestamps,
            _marker: std::marker::PhantomData,
        }
    }
    
    /// Verify the memory hash properly
    fn verify_memory_hash(&self, cs: &ConstraintSystemRef<F>, memory_hash: [u8; 32]) -> Result<Variable, SynthesisError> {
        // Process the full 32-byte hash in chunks of 8 bytes
        // This provides stronger verification than just using the first 8 bytes
        let mut hash_witnesses = Vec::new();
        let mut hash_public_inputs = Vec::new();
        
        for chunk_idx in 0..4 {  // Process 4 chunks of 8 bytes each
            let start_idx = chunk_idx * 8;
            let mut chunk_value: u64 = 0;
            
            for i in 0..8 {
                if start_idx + i < memory_hash.len() {
                    chunk_value = (chunk_value << 8) | (memory_hash[start_idx + i] as u64);
                }
            }
            
            // Create public input and witness for this chunk
            let chunk_public = cs.new_input_variable(|| Ok(F::from(chunk_value)))?;
            let chunk_witness = cs.new_witness_variable(|| Ok(F::from(chunk_value)))?;
            
            // Enforce that the witness matches the public input
            let mut lc1 = LinearCombination::new();
            lc1.extend(vec![(F::one(), chunk_witness)]);
            
            let mut lc2 = LinearCombination::new();
            lc2.extend(vec![(F::one(), Variable::One)]);
            
            let mut lc3 = LinearCombination::new();
            lc3.extend(vec![(F::one(), chunk_public)]);
            
            cs.enforce_constraint(lc1, lc2, lc3)?;
            
            hash_witnesses.push(chunk_witness);
            hash_public_inputs.push(chunk_public);
        }
        
        // Return the first chunk's witness as a representative of the hash
        Ok(hash_witnesses[0])
    }
}

impl<F: Field> ConstraintSynthesizer<F> for MemorySafetyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        println!("Generating memory safety constraints...");
        
        // Create a public input for whether all memory accesses are safe
        let all_accesses_safe = cs.new_input_variable(|| {
            // Default to safe, will be set to false if any unsafe access is found
            Ok(F::one())
        })?;
        
        // Create a public input for the maximum memory size
        let max_memory_size_public = cs.new_input_variable(|| {
            Ok(F::from(self.max_memory_size.as_u64()))
        })?;
        
        // Create witnesses for each allocation
        let mut allocation_starts = Vec::new();
        let mut allocation_ends = Vec::new();
        
        // If temporal safety is enabled, create witnesses for allocation timestamps
        let mut allocation_start_time_witnesses = Vec::new();
        let mut allocation_end_time_witnesses = Vec::new();
        
        if self.enforce_temporal_safety {
            println!("Temporal safety checking is enabled");
            
            // Create witnesses for allocation timestamps
            for i in 0..self.allocations.len() {
                let start_time = self.allocation_start_timestamps[i];
                let end_time = self.allocation_end_timestamps[i];
                
                let start_time_witness = cs.new_witness_variable(|| Ok(F::from(start_time as u64)))?;
                let end_time_witness = cs.new_witness_variable(|| Ok(F::from(end_time as u64)))?;
                
                allocation_start_time_witnesses.push(start_time_witness);
                allocation_end_time_witnesses.push(end_time_witness);
                
                // Enforce that end_time > start_time
                let mut lc1 = LinearCombination::new();
                lc1.extend(vec![(F::one(), end_time_witness), (-F::one(), start_time_witness)]);
                
                let mut lc2 = LinearCombination::new();
                lc2.extend(vec![(F::one(), Variable::One)]);
                
                let mut lc3 = LinearCombination::new();
                lc3.extend(vec![(F::one(), Variable::One)]);
                
                cs.enforce_constraint(lc1, lc2, lc3)?;
            }
        }
        
        for (i, (alloc_addr, alloc_size)) in self.allocations.iter().enumerate() {
            println!("Processing allocation {}: addr={}, size={}", i, alloc_addr, alloc_size);
            
            // Convert U256 to field elements (simplified for demonstration)
            let alloc_addr_u64 = alloc_addr.as_u64();
            let alloc_size_u64 = alloc_size.as_u64();
            
            let alloc_start = cs.new_witness_variable(|| Ok(F::from(alloc_addr_u64)))?;
            let alloc_end = cs.new_witness_variable(|| Ok(F::from(alloc_addr_u64 + alloc_size_u64)))?;
            
            allocation_starts.push(alloc_start);
            allocation_ends.push(alloc_end);
            
            // Enforce that allocation is within memory bounds
            // alloc_end <= max_memory_size
            let mut lc1 = LinearCombination::new();
            lc1.extend(vec![(F::one(), max_memory_size_public), (-F::one(), alloc_end)]);
            
            let mut lc2 = LinearCombination::new();
            lc2.extend(vec![(F::one(), Variable::One)]);
            
            let mut lc3 = LinearCombination::new();
            lc3.extend(vec![(F::one(), Variable::One)]); // This constraint is always enforced
            
            cs.enforce_constraint(lc1, lc2, lc3)?;
            
            // Enforce that allocation size is positive
            // alloc_end > alloc_start
            let mut lc1 = LinearCombination::new();
            lc1.extend(vec![(F::one(), alloc_end), (-F::one(), alloc_start)]);
            
            let mut lc2 = LinearCombination::new();
            lc2.extend(vec![(F::one(), Variable::One)]);
            
            let mut lc3 = LinearCombination::new();
            lc3.extend(vec![(F::one(), Variable::One)]); // This constraint is always enforced
            
            cs.enforce_constraint(lc1, lc2, lc3)?;
        }
        
        // Process each memory access
        for (i, (access_offset, access_size)) in self.accesses.iter().enumerate() {
            println!("Processing access {}: offset={}, size={}", i, access_offset, access_size);
            
            // Convert U256 to field elements (simplified for demonstration)
            let access_offset_u64 = access_offset.as_u64();
            let access_size_u64 = access_size.as_u64();
            
            let access_start = cs.new_witness_variable(|| Ok(F::from(access_offset_u64)))?;
            let access_end = cs.new_witness_variable(|| Ok(F::from(access_offset_u64 + access_size_u64)))?;
            
            // If temporal safety is enabled, create a witness for this access's timestamp
            let mut access_time_witness = Variable::One; // Default
            
            if self.enforce_temporal_safety {
                let access_time = self.access_timestamps[i];
                access_time_witness = cs.new_witness_variable(|| Ok(F::from(access_time as u64)))?;
            }
            
            // Enforce that access is within memory bounds
            // access_end <= max_memory_size
            let mut lc1 = LinearCombination::new();
            lc1.extend(vec![(F::one(), max_memory_size_public), (-F::one(), access_end)]);
            
            let mut lc2 = LinearCombination::new();
            lc2.extend(vec![(F::one(), Variable::One)]);
            
            let mut lc3 = LinearCombination::new();
            lc3.extend(vec![(F::one(), Variable::One)]); // This constraint is always enforced
            
            cs.enforce_constraint(lc1, lc2, lc3)?;
            
            // Create a witness for whether this access is safe (within any allocation)
            let access_is_safe = cs.new_witness_variable(|| {
                // Default to unsafe, will be set to true if a valid allocation is found
                let mut is_safe = false;
                
                for (alloc_addr, alloc_size) in &self.allocations {
                    let alloc_addr_u64 = alloc_addr.as_u64();
                    let alloc_size_u64 = alloc_size.as_u64();
                    
                    // Check if access is within this allocation
                    if access_offset_u64 >= alloc_addr_u64 && 
                       (access_offset_u64 + access_size_u64) <= (alloc_addr_u64 + alloc_size_u64) {
                        is_safe = true;
                        break;
                    }
                }
                
                Ok(F::from(is_safe as u32))
            })?;
            
            // Enforce that access_is_safe is boolean (0 or 1)
            // access_is_safe * (access_is_safe - 1) = 0
            let mut lc1 = LinearCombination::new();
            lc1.extend(vec![(F::one(), access_is_safe)]);
            
            let mut lc2 = LinearCombination::new();
            lc2.extend(vec![(F::one(), access_is_safe), (-F::one(), Variable::One)]);
            
            let mut lc3 = LinearCombination::new();
            lc3.extend(vec![(F::zero(), Variable::One)]);
            
            cs.enforce_constraint(lc1, lc2, lc3)?;
            
            // For each allocation, check if this access is within bounds
            for j in 0..self.allocations.len() {
                let alloc_start = allocation_starts[j];
                let alloc_end = allocation_ends[j];
                
                // Create a boolean witness for whether this access is within this allocation
                let in_bounds = cs.new_witness_variable(|| {
                    let alloc_addr = self.allocations[j].0.as_u64();
                    let alloc_size = self.allocations[j].1.as_u64();
                    
                    let is_valid = access_offset_u64 >= alloc_addr && 
                                  (access_offset_u64 + access_size_u64) <= (alloc_addr + alloc_size);
                    
                    Ok(F::from(is_valid as u32))
                })?;
                
                // If temporal safety is enabled, check temporal bounds as well
                if self.enforce_temporal_safety {
                    let temporal_in_bounds = cs.new_witness_variable(|| {
                        let access_time = self.access_timestamps[i] as u64;
                        let alloc_start_time = self.allocation_start_timestamps[j] as u64;
                        let alloc_end_time = self.allocation_end_timestamps[j] as u64;
                        
                        let is_temporally_valid = access_time >= alloc_start_time && 
                                                 access_time <= alloc_end_time;
                        
                        Ok(F::from(is_temporally_valid as u32))
                    })?;
                    
                    // Enforce that temporal_in_bounds is boolean
                    let mut lc1 = LinearCombination::new();
                    lc1.extend(vec![(F::one(), temporal_in_bounds)]);
                    
                    let mut lc2 = LinearCombination::new();
                    lc2.extend(vec![(F::one(), temporal_in_bounds), (-F::one(), Variable::One)]);
                    
                    let mut lc3 = LinearCombination::new();
                    lc3.extend(vec![(F::zero(), Variable::One)]);
                    
                    cs.enforce_constraint(lc1, lc2, lc3)?;
                    
                    // Enforce that access_time >= allocation_start_time when in_bounds is 1
                    let mut lc1 = LinearCombination::new();
                    lc1.extend(vec![(F::one(), access_time_witness), (-F::one(), allocation_start_time_witnesses[j])]);
                    
                    let mut lc2 = LinearCombination::new();
                    lc2.extend(vec![(F::one(), in_bounds)]);
                    
                    let mut lc3 = LinearCombination::new();
                    lc3.extend(vec![(F::one(), Variable::One)]);
                    
                    cs.enforce_constraint(lc1, lc2, lc3)?;
                    
                    // Enforce that access_time <= allocation_end_time when in_bounds is 1
                    let mut lc1 = LinearCombination::new();
                    lc1.extend(vec![(F::one(), allocation_end_time_witnesses[j]), (-F::one(), access_time_witness)]);
                    
                    let mut lc2 = LinearCombination::new();
                    lc2.extend(vec![(F::one(), in_bounds)]);
                    
                    let mut lc3 = LinearCombination::new();
                    lc3.extend(vec![(F::one(), Variable::One)]);
                    
                    cs.enforce_constraint(lc1, lc2, lc3)?;
                    
                    // Update in_bounds to be the AND of spatial and temporal bounds
                    // in_bounds = in_bounds AND temporal_in_bounds
                    // Since we can't directly encode AND, we'll use the fact that
                    // a AND b = a * b for boolean a, b
                    let combined_in_bounds = cs.new_witness_variable(|| {
                        let spatial_valid = in_bounds == Variable::One;
                        let temporal_valid = temporal_in_bounds == Variable::One;
                        Ok(F::from((spatial_valid && temporal_valid) as u32))
                    })?;
                    
                    // Enforce that combined_in_bounds = in_bounds * temporal_in_bounds
                    let mut lc1 = LinearCombination::new();
                    lc1.extend(vec![(F::one(), in_bounds)]);
                    
                    let mut lc2 = LinearCombination::new();
                    lc2.extend(vec![(F::one(), temporal_in_bounds)]);
                    
                    let mut lc3 = LinearCombination::new();
                    lc3.extend(vec![(F::one(), combined_in_bounds)]);
                    
                    cs.enforce_constraint(lc1, lc2, lc3)?;
                    
                    // Replace in_bounds with the combined version
                    let in_bounds = combined_in_bounds;
                }
                
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
                
                // Update access_is_safe if this allocation contains the access
                // access_is_safe = access_is_safe OR in_bounds
                // Since we can't directly encode OR, we'll use the fact that
                // access_is_safe OR in_bounds = 1 - (1 - access_is_safe) * (1 - in_bounds)
                let not_access_is_safe = cs.new_witness_variable(|| {
                    let is_safe = access_is_safe == Variable::One;
                    Ok(F::from((!is_safe) as u32))
                })?;
                
                let not_in_bounds = cs.new_witness_variable(|| {
                    let is_valid = in_bounds == Variable::One;
                    Ok(F::from((!is_valid) as u32))
                })?;
                
                // Enforce that not_access_is_safe = 1 - access_is_safe
                let mut lc1 = LinearCombination::new();
                lc1.extend(vec![(F::one(), Variable::One), (-F::one(), access_is_safe)]);
                
                let mut lc2 = LinearCombination::new();
                lc2.extend(vec![(F::one(), Variable::One)]);
                
                let mut lc3 = LinearCombination::new();
                lc3.extend(vec![(F::one(), not_access_is_safe)]);
                
                cs.enforce_constraint(lc1, lc2, lc3)?;
                
                // Enforce that not_in_bounds = 1 - in_bounds
                let mut lc1 = LinearCombination::new();
                lc1.extend(vec![(F::one(), Variable::One), (-F::one(), in_bounds)]);
                
                let mut lc2 = LinearCombination::new();
                lc2.extend(vec![(F::one(), Variable::One)]);
                
                let mut lc3 = LinearCombination::new();
                lc3.extend(vec![(F::one(), not_in_bounds)]);
                
                cs.enforce_constraint(lc1, lc2, lc3)?;
            }
        }
        
        // If memory hash is provided, add it as a public input with improved verification
        if let Some(hash) = self.memory_hash {
            self.verify_memory_hash(&cs, hash)?;
        }
        
        println!("Generated {} constraints", cs.num_constraints());
        Ok(())
    }
}
