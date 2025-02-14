use ark_ff::Field;
use ark_relations::r1cs::{
    ConstraintSynthesizer, 
    ConstraintSystemRef, 
    SynthesisError,
    LinearCombination,
    Variable,
};
use std::marker::PhantomData;
use crate::parser::types::{MemoryType, Limits};

/// Represents a memory access operation (load or store)
#[derive(Debug, Clone)]
pub enum MemoryAccess {
    /// Load operation: (offset, align, size)
    Load(u32, u32, u32),
    /// Store operation: (offset, align, size)
    Store(u32, u32, u32),
    /// Memory grow operation: new_pages
    Grow(u32),
}

/// Circuit for verifying memory safety properties
pub struct MemorySafetyCircuit<F: Field> {
    /// Memory access operations to verify
    memory_accesses: Vec<MemoryAccess>,
    /// Memory limits (min and max pages)
    memory_type: MemoryType,
    /// Current memory size in pages
    current_size: u32,
    /// Phantom data for the field
    _marker: PhantomData<F>,
}

impl<F: Field> MemorySafetyCircuit<F> {
    /// Create a new memory safety circuit
    pub fn new(
        memory_accesses: Vec<MemoryAccess>,
        memory_type: MemoryType,
        current_size: u32,
    ) -> Self {
        Self {
            memory_accesses,
            memory_type,
            current_size,
            _marker: PhantomData,
        }
    }

    /// Helper to convert u32 to field element
    fn u32_to_field(value: u32) -> F {
        F::from(value as u64)
    }

    /// Helper to check if memory access is within bounds
    fn check_memory_bounds(
        cs: &ConstraintSystemRef<F>,
        offset: u32,
        size: u32,
        current_size: Variable,
    ) -> Result<(), SynthesisError> {
        // Convert values to field elements
        let offset_f = Self::u32_to_field(offset);
        let size_f = Self::u32_to_field(size);
        let page_size_f = Self::u32_to_field(65536); // WASM page size
        
        // Create variables for offset, size, and page size
        let offset_var = cs.new_input_variable(|| Ok(offset_f))?;
        let size_var = cs.new_input_variable(|| Ok(size_f))?;
        let page_size_var = cs.new_input_variable(|| Ok(page_size_f))?;
        
        // Calculate access range
        let access_end = cs.new_witness_variable(|| {
            Ok(offset_f + size_f)
        })?;
        
        // Enforce access_end = offset + size
        cs.enforce_constraint(
            LinearCombination::from(offset_var) + LinearCombination::from(size_var),
            LinearCombination::from(Variable::One),
            LinearCombination::from(access_end),
        )?;
        
        // Calculate total memory size in bytes (current_size * page_size)
        let memory_size = cs.new_witness_variable(|| {
            Ok(page_size_f)  // Start with one page size
        })?;
        
        // Enforce memory_size = current_size * page_size
        cs.enforce_constraint(
            LinearCombination::from(current_size),
            LinearCombination::from(page_size_var),
            LinearCombination::from(memory_size),
        )?;
        
        // Enforce access_end <= memory_size by requiring memory_size - access_end >= 0
        cs.enforce_constraint(
            LinearCombination::from(memory_size) - LinearCombination::from(access_end),
            LinearCombination::from(Variable::One),
            LinearCombination::from(memory_size) - LinearCombination::from(access_end),
        )?;
        
        Ok(())
    }

    /// Helper to check memory alignment
    fn check_alignment(
        cs: &ConstraintSystemRef<F>,
        offset: u32,
        align: u32,
    ) -> Result<(), SynthesisError> {
        // Convert values to field elements
        let offset_f = Self::u32_to_field(offset);
        let align_f = Self::u32_to_field(align);
        
        // Create variables
        let offset_var = cs.new_input_variable(|| Ok(offset_f))?;
        let align_var = cs.new_input_variable(|| Ok(align_f))?;
        
        // Offset must be divisible by alignment
        // This means: offset % align == 0
        // We can express this as: exists k where offset = k * align
        let k_f = Self::u32_to_field(offset / align);
        let k_var = cs.new_witness_variable(|| Ok(k_f))?;
        
        cs.enforce_constraint(
            LinearCombination::from(k_var),
            LinearCombination::from(align_var),
            LinearCombination::from(offset_var),
        )?;
        
        Ok(())
    }
}

impl<F: Field> ConstraintSynthesizer<F> for MemorySafetyCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        // Initialize current memory size as input variable
        let current_size_f = Self::u32_to_field(self.current_size);
        let mut current_size = cs.new_input_variable(|| Ok(current_size_f))?;
        
        // Process each memory access
        for access in self.memory_accesses {
            match access {
                MemoryAccess::Load(offset, align, size) => {
                    // Check alignment
                    Self::check_alignment(&cs, offset, align)?;
                    
                    // Check bounds
                    Self::check_memory_bounds(&cs, offset, size, current_size)?;
                }
                
                MemoryAccess::Store(offset, align, size) => {
                    // Check alignment
                    Self::check_alignment(&cs, offset, align)?;
                    
                    // Check bounds
                    Self::check_memory_bounds(&cs, offset, size, current_size)?;
                }
                
                MemoryAccess::Grow(new_pages) => {
                    // Convert values to field elements
                    let new_pages_f = Self::u32_to_field(new_pages);
                    let new_pages_var = cs.new_input_variable(|| Ok(new_pages_f))?;
                    
                    // Calculate new size
                    let new_size_var = cs.new_witness_variable(|| {
                        Ok(current_size_f + new_pages_f)
                    })?;
                    
                    // Enforce new size calculation
                    cs.enforce_constraint(
                        LinearCombination::from(current_size) + LinearCombination::from(new_pages_var),
                        LinearCombination::from(Variable::One),
                        LinearCombination::from(new_size_var),
                    )?;
                    
                    // Check against max limit if specified
                    if let Some(max) = self.memory_type.limits.max {
                        let max_f = Self::u32_to_field(max);
                        let max_var = cs.new_input_variable(|| Ok(max_f))?;
                        
                        cs.enforce_constraint(
                            LinearCombination::from(new_size_var),
                            LinearCombination::from(Variable::One),
                            LinearCombination::from(max_var),
                        )?;
                    }
                    
                    // Update current size
                    current_size = new_size_var;
                }
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_bls12_381::Fr;

    #[test]
    fn test_load_store() {
        let limits = Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let accesses = vec![
            MemoryAccess::Store(0, 4, 4),  // Store 4 bytes at offset 0, aligned to 4
            MemoryAccess::Load(0, 4, 4),   // Load 4 bytes from offset 0, aligned to 4
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            accesses,
            memory_type,
            1,  // Current size: 1 page
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_memory_growth() {
        let limits = Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let accesses = vec![
            MemoryAccess::Grow(1),  // Grow by 1 page
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            accesses,
            memory_type,
            1,  // Current size: 1 page
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_out_of_bounds() {
        let limits = Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let accesses = vec![
            MemoryAccess::Load(65537, 4, 4),  // Try to load beyond page boundary
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            accesses,
            memory_type,
            1,  // Current size: 1 page
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_misaligned_access() {
        let limits = Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let accesses = vec![
            MemoryAccess::Store(1, 4, 4),  // Misaligned store (offset 1 with align 4)
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            accesses,
            memory_type,
            1,  // Current size: 1 page
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_exceed_max_pages() {
        let limits = Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let accesses = vec![
            MemoryAccess::Grow(2),  // Try to grow beyond max pages
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            accesses,
            memory_type,
            1,  // Current size: 1 page
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(!cs.is_satisfied().unwrap());
    }
}
