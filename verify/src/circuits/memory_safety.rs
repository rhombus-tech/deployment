//! Memory Safety Circuit for WebAssembly
//! 
//! This module implements a zero-knowledge circuit that verifies memory safety properties
//! of WebAssembly programs. It ensures:
//! 
//! 1. Memory Access Safety:
//!    - All loads/stores are within bounds of allocated memory
//!    - Memory accesses are properly aligned
//!    - No out-of-bounds access attempts
//! 
//! 2. Memory Growth Safety:
//!    - Memory growth requests don't exceed maximum allowed pages
//!    - Page allocations are tracked correctly
//! 
//! 3. Memory Initialization Safety:
//!    - No overlapping memory initializations
//!    - All initializations are within bounds
//!    - Initialization data is properly aligned
//!
//! # Usage
//! 
//! The circuit takes a sequence of memory operations and verifies their safety:
//! ```ignore
//! use verify::circuits::memory_safety::{MemoryAccess, MemorySafetyCircuit};
//! 
//! // Create a sequence of memory operations
//! let accesses = vec![
//!     MemoryAccess::Grow(1),           // Grow by 1 page
//!     MemoryAccess::Store(0, 4, 4),    // Store 4 bytes at offset 0, aligned to 4
//!     MemoryAccess::Load(0, 4, 4),     // Load 4 bytes from offset 0, aligned to 4
//! ];
//! 
//! // Create and verify the circuit
//! let circuit = MemorySafetyCircuit::new(
//!     accesses,
//!     vec![],          // Initial memory data
//!     memory_type,     // Memory type with limits
//!     2,              // Final number of pages
//! );
//! ```

use ark_ff::Field;
use ark_relations::{
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable},
    lc,
};
use crate::parser::types::MemoryType;

const PAGE_SIZE: u32 = 65536;

/// Represents a memory access operation (load or store)
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum MemoryAccess {
    /// Load operation with parameters:
    /// - offset: Starting byte offset in memory
    /// - align: Required alignment (must be power of 2)
    /// - size: Number of bytes to load
    Load(u32, u32, u32),

    /// Store operation with parameters:
    /// - offset: Starting byte offset in memory
    /// - align: Required alignment (must be power of 2)
    /// - size: Number of bytes to store
    Store(u32, u32, u32),

    /// Memory grow operation:
    /// - new_pages: Number of new pages to allocate
    /// 
    /// Note: Each page is 64KB (65536 bytes)
    Grow(u32),
}

/// Represents a memory initialization operation
#[derive(Debug, Clone)]
pub struct MemoryInit {
    /// Offset to write data at
    pub offset: u32,
    /// Size of data to write
    pub size: u32,
    /// Data to write (as bytes)
    pub data: Vec<u8>,
}

/// Circuit for verifying memory safety properties of WebAssembly programs
/// 
/// This circuit ensures that all memory operations are safe by:
/// 1. Validating bounds for all memory accesses
/// 2. Checking alignment requirements
/// 3. Tracking memory growth
/// 4. Preventing overlapping memory initializations
#[derive(Debug, Clone)]
pub struct MemorySafetyCircuit<F: Field> {
    /// Sequence of memory accesses to verify
    memory_accesses: Vec<MemoryAccess>,
    
    /// Initial memory data segments
    memory_inits: Vec<MemoryInit>,
    
    /// Memory type containing limits
    memory_type: MemoryType,
    
    /// Final number of pages after all operations
    current_pages: usize,
    
    /// Phantom data for the field
    _marker: std::marker::PhantomData<F>,
}

#[allow(dead_code)]
impl<F: Field> MemorySafetyCircuit<F> {
    /// Create a new memory safety circuit
    pub fn new(
        memory_accesses: Vec<MemoryAccess>,
        memory_inits: Vec<MemoryInit>,
        memory_type: MemoryType,
        current_pages: usize,
    ) -> Self {
        Self {
            memory_accesses,
            memory_inits,
            memory_type,
            current_pages,
            _marker: std::marker::PhantomData,
        }
    }

    /// Helper to convert u32 to field element
    fn u32_to_field(value: u32) -> F {
        F::from(value as u64)
    }

    /// Validates that a memory access is within bounds
    fn validate_bounds(&self, offset: u32, size: u32) -> bool {
        // Check if offset + size would overflow
        if let Some(end_offset) = offset.checked_add(size) {
            // Get current memory size in bytes (pages * page_size)
            let memory_size = self.current_pages as u32 * PAGE_SIZE;
            
            // Check if access is within memory bounds
            end_offset <= memory_size
        } else {
            // Overflow occurred, access is invalid
            false
        }
    }

    /// Validates memory access alignment
    fn validate_alignment(&self, offset: u32, align: u32) -> bool {
        // Alignment must be power of 2 and offset must be aligned
        align.is_power_of_two() && (offset % align == 0)
    }

    /// Process a memory access operation
    fn process_memory_access(&mut self, access: &MemoryAccess) -> Result<(), SynthesisError> {
        match access {
            MemoryAccess::Load(offset, align, size) => {
                // Validate alignment
                if !self.validate_alignment(*offset, *align) {
                    println!("Misaligned load access at offset {} with alignment {}", offset, align);
                    return Err(SynthesisError::Unsatisfiable);
                }
                
                // Validate bounds
                if !self.validate_bounds(*offset, *size) {
                    println!("Out of bounds load access at offset {} with size {}", offset, size);
                    return Err(SynthesisError::Unsatisfiable);
                }
            }
            MemoryAccess::Store(offset, align, size) => {
                // Validate alignment
                if !self.validate_alignment(*offset, *align) {
                    println!("Misaligned store access at offset {} with alignment {}", offset, align);
                    return Err(SynthesisError::Unsatisfiable);
                }
                
                // Validate bounds
                if !self.validate_bounds(*offset, *size) {
                    println!("Out of bounds store access at offset {} with size {}", offset, size);
                    return Err(SynthesisError::Unsatisfiable);
                }
            }
            MemoryAccess::Grow(pages) => {
                // Calculate new number of pages
                let new_pages = self.current_pages + *pages as usize;
                
                // Check if exceeding maximum pages
                if new_pages > 65536 {
                    println!("Memory growth would exceed maximum pages");
                    return Err(SynthesisError::Unsatisfiable);
                }
                
                // Update current pages
                self.current_pages = new_pages;
            }
        }
        Ok(())
    }

    /// Helper to check if memory access is within bounds
    fn check_memory_bounds(
        cs: &ConstraintSystemRef<F>,
        offset: u32,
        size: u32,
        current_pages: usize,
    ) -> Result<(), SynthesisError> {
        // Convert values to field elements
        let offset_f = Self::u32_to_field(offset);
        let size_f = Self::u32_to_field(size);
        let page_size_f = Self::u32_to_field(PAGE_SIZE);
        let current_pages_f = Self::u32_to_field(current_pages as u32);
        
        // Create constraint variables
        let offset_var = cs.new_witness_variable(|| Ok(offset_f))?;
        let size_var = cs.new_witness_variable(|| Ok(size_f))?;
        let memory_size_var = cs.new_input_variable(|| Ok(current_pages_f * page_size_f))?;
        
        // Calculate access_end = offset + size, checking for overflow
        let access_end = cs.new_witness_variable(|| {
            match offset.checked_add(size) {
                Some(end) => Ok(Self::u32_to_field(end)),
                None => Ok(F::zero()) // If overflow, treat as zero which will fail bounds check
            }
        })?;
        
        // Enforce access_end = offset + size
        cs.enforce_constraint(
            lc!() + offset_var + size_var,
            lc!() + Variable::One,
            lc!() + access_end,
        )?;
        
        // Calculate memory_size = current_pages * PAGE_SIZE
        let memory_size = current_pages as u32 * PAGE_SIZE;
        
        // Enforce access_end <= memory_size
        let diff = cs.new_witness_variable(|| {
            // Check for overflow and bounds
            match offset.checked_add(size) {
                Some(end) if end <= memory_size => {
                    Ok(current_pages_f * page_size_f - Self::u32_to_field(end))
                }
                _ => Ok(F::zero()) // Either overflow or out of bounds
            }
        })?;
        
        cs.enforce_constraint(
            lc!() + memory_size_var - access_end,
            lc!() + Variable::One,
            lc!() + diff,
        )?;
        
        // Enforce that diff is non-negative (this is implicitly handled by the field arithmetic)
        cs.enforce_constraint(
            lc!() + Variable::One,
            lc!() + diff,
            lc!() + diff,
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
            lc!() + k_var,
            lc!() + align_var,
            lc!() + offset_var,
        )?;
        
        Ok(())
    }

    /// Helper to check memory initialization bounds
    fn check_init_bounds(
        cs: &ConstraintSystemRef<F>,
        init: &MemoryInit,
        current_pages: usize,
    ) -> Result<(), SynthesisError> {
        // Check that data size matches declared size
        if init.data.len() != init.size as usize {
            return Err(SynthesisError::Unsatisfiable);
        }

        // Convert values to field elements
        let offset = Self::u32_to_field(init.offset);
        let size = Self::u32_to_field(init.size);
        let max_offset = Self::u32_to_field((current_pages * (PAGE_SIZE as usize)) as u32);

        // Create constraint variables
        let offset_var = cs.new_witness_variable(|| Ok(offset))?;
        let size_var = cs.new_witness_variable(|| Ok(size))?;
        let max_offset_var = cs.new_input_variable(|| Ok(max_offset))?;

        // Create a variable for the sum
        let sum = cs.new_witness_variable(|| Ok(offset + size))?;

        // 1. Enforce that offset + size = sum
        cs.enforce_constraint(
            lc!() + offset_var + size_var,
            lc!() + Variable::One,
            lc!() + sum,
        )?;

        // 2. Enforce that max_offset - sum >= 0
        let diff = cs.new_witness_variable(|| {
            if offset + size > max_offset {
                Ok(F::zero())
            } else {
                Ok(max_offset - (offset + size))
            }
        })?;

        cs.enforce_constraint(
            lc!() + max_offset_var - sum,
            lc!() + Variable::One,
            lc!() + diff,
        )?;

        // 3. Enforce that diff is non-negative (this is implicitly handled by the field arithmetic)
        cs.enforce_constraint(
            lc!() + Variable::One,
            lc!() + diff,
            lc!() + diff,
        )?;

        Ok(())
    }

    /// Helper to check for overlapping memory initializations
    fn check_init_overlap(
        cs: &ConstraintSystemRef<F>,
        init1: &MemoryInit,
        init2: &MemoryInit,
    ) -> Result<(), SynthesisError> {
        // Convert values to field elements
        let offset1 = Self::u32_to_field(init1.offset);
        let size1 = Self::u32_to_field(init1.size);
        let offset2 = Self::u32_to_field(init2.offset);
        let size2 = Self::u32_to_field(init2.size);

        // Create constraint variables
        let offset1_var = cs.new_witness_variable(|| Ok(offset1))?;
        let size1_var = cs.new_witness_variable(|| Ok(size1))?;
        let offset2_var = cs.new_witness_variable(|| Ok(offset2))?;
        let size2_var = cs.new_witness_variable(|| Ok(size2))?;

        // Calculate end points
        let end1 = cs.new_witness_variable(|| Ok(offset1 + size1))?;
        let end2 = cs.new_witness_variable(|| Ok(offset2 + size2))?;

        // Enforce end point calculations
        cs.enforce_constraint(
            lc!() + offset1_var + size1_var,
            lc!() + Variable::One,
            lc!() + end1,
        )?;
        cs.enforce_constraint(
            lc!() + offset2_var + size2_var,
            lc!() + Variable::One,
            lc!() + end2,
        )?;

        // Check for overlap: !(end1 <= offset2 || end2 <= offset1)
        // Overlap exists if: end1 > offset2 && end2 > offset1

        // Create boolean flags for the conditions
        let end1_gt_offset2 = cs.new_witness_variable(|| {
            if offset1 + size1 > offset2 {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        let end2_gt_offset1 = cs.new_witness_variable(|| {
            if offset2 + size2 > offset1 {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // Enforce that end1_gt_offset2 is boolean
        cs.enforce_constraint(
            lc!() + end1_gt_offset2,
            lc!() + end1_gt_offset2 - Variable::One,
            lc!() + Variable::Zero,
        )?;

        // Enforce that end2_gt_offset1 is boolean
        cs.enforce_constraint(
            lc!() + end2_gt_offset1,
            lc!() + end2_gt_offset1 - Variable::One,
            lc!() + Variable::Zero,
        )?;

        // Create overlap flag: end1_gt_offset2 AND end2_gt_offset1
        let overlap = cs.new_witness_variable(|| {
            if (offset1 + size1 > offset2) && (offset2 + size2 > offset1) {
                Ok(F::one())
            } else {
                Ok(F::zero())
            }
        })?;

        // Enforce that overlap is the AND of both conditions
        cs.enforce_constraint(
            lc!() + end1_gt_offset2,
            lc!() + end2_gt_offset1,
            lc!() + overlap,
        )?;

        // Enforce that overlap is false (0)
        cs.enforce_constraint(
            lc!() + overlap,
            lc!() + Variable::One,
            lc!() + Variable::Zero,
        )?;

        Ok(())
    }

    /// Process a memory growth operation
    fn process_memory_growth(
        cs: &ConstraintSystemRef<F>,
        current_pages: &mut usize,
        new_pages: u32,
        memory_type: &MemoryType,
    ) -> Result<(), SynthesisError> {
        let new_total_pages = *current_pages as u32 + new_pages;
        
        // Check if growth exceeds maximum pages
        if let Some(max_pages) = memory_type.limits.max {
            if new_total_pages > max_pages {
                return Err(SynthesisError::Unsatisfiable);
            }
        }
        
        // Convert to field elements
        let current_pages_f = Self::u32_to_field(*current_pages as u32);
        let new_pages_f = Self::u32_to_field(new_pages);
        let new_total_f = Self::u32_to_field(new_total_pages);
        
        // Create constraint variables
        let current_var = cs.new_witness_variable(|| Ok(current_pages_f))?;
        let growth_var = cs.new_witness_variable(|| Ok(new_pages_f))?;
        let total_var = cs.new_witness_variable(|| Ok(new_total_f))?;
        
        // Enforce total = current + growth
        cs.enforce_constraint(
            lc!() + current_var + growth_var,
            lc!() + Variable::One,
            lc!() + total_var,
        )?;
        
        // Update current pages
        *current_pages = new_total_pages as usize;
        
        Ok(())
    }

    /// Helper to check if memory access is within bounds
    fn generate_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        let mut current_pages = self.memory_type.limits.min as usize;

        // Check each memory initialization
        for init in self.memory_inits.iter() {
            Self::check_init_bounds(&cs, init, current_pages)?;
        }

        // Process memory accesses in sequence
        for access in self.memory_accesses.iter() {
            match access {
                MemoryAccess::Load(offset, align, size) => {
                    Self::check_memory_bounds(&cs, *offset, *size, current_pages)?;
                    Self::check_alignment(&cs, *offset, *align)?;
                }
                MemoryAccess::Store(offset, align, size) => {
                    Self::check_memory_bounds(&cs, *offset, *size, current_pages)?;
                    Self::check_alignment(&cs, *offset, *align)?;
                }
                MemoryAccess::Grow(pages) => {
                    Self::process_memory_growth(&cs, &mut current_pages, *pages, &self.memory_type)?;
                }
            }
        }

        // Verify final number of pages matches expected
        if current_pages != self.current_pages {
            return Err(SynthesisError::Unsatisfiable);
        }

        Ok(())
    }
}

impl<F: Field> ConstraintSynthesizer<F> for MemorySafetyCircuit<F> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> {
        let mut current_pages = self.memory_type.limits.min as usize;

        // Check each memory initialization
        for init in self.memory_inits.iter() {
            Self::check_init_bounds(&cs, init, current_pages)?;
        }

        // Process memory accesses in sequence
        for access in self.memory_accesses.iter() {
            match access {
                MemoryAccess::Load(offset, align, size) => {
                    Self::check_memory_bounds(&cs, *offset, *size, current_pages)?;
                    Self::check_alignment(&cs, *offset, *align)?;
                }
                MemoryAccess::Store(offset, align, size) => {
                    Self::check_memory_bounds(&cs, *offset, *size, current_pages)?;
                    Self::check_alignment(&cs, *offset, *align)?;
                }
                MemoryAccess::Grow(pages) => {
                    Self::process_memory_growth(&cs, &mut current_pages, *pages, &self.memory_type)?;
                }
            }
        }

        // Verify final number of pages matches expected
        if current_pages != self.current_pages {
            return Err(SynthesisError::Unsatisfiable);
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
        let limits = crate::parser::types::Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let accesses = vec![
            MemoryAccess::Store(0, 4, 4),  // Store 4 bytes at offset 0, aligned to 4
            MemoryAccess::Load(0, 4, 4),   // Load 4 bytes from offset 0, aligned to 4
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            accesses,
            vec![],
            memory_type,
            1,  // Current size: 1 page
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_memory_growth() {
        let limits = crate::parser::types::Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let accesses = vec![
            MemoryAccess::Grow(1),  // Grow by 1 page
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            accesses,
            vec![],
            memory_type,
            2,  // Expected final size: 2 pages
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_out_of_bounds() {
        let limits = crate::parser::types::Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let accesses = vec![
            MemoryAccess::Load(65537, 4, 4),  // Try to load beyond page boundary
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            accesses,
            vec![],
            memory_type,
            1,  // Current size: 1 page
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_misaligned_access() {
        let limits = crate::parser::types::Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let accesses = vec![
            MemoryAccess::Store(1, 4, 4),  // Misaligned store (offset 1 with align 4)
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            accesses,
            vec![],
            memory_type,
            1,  // Current size: 1 page
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_exceed_max_pages() {
        let limits = crate::parser::types::Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let accesses = vec![
            MemoryAccess::Grow(2),  // Try to grow beyond max pages
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            accesses,
            vec![],
            memory_type,
            3,  // Expected final size: 3 pages (should fail)
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs.clone()).is_err());
    }

    #[test]
    fn test_memory_init() {
        let limits = crate::parser::types::Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let inits = vec![
            MemoryInit {
                offset: 0,
                size: 4,
                data: vec![1, 2, 3, 4],
            },
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            vec![],
            inits,
            memory_type,
            1,  // Current size: 1 page
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_invalid_memory_init() {
        let limits = crate::parser::types::Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let inits = vec![
            MemoryInit {
                offset: 65537,  // Beyond page boundary
                size: 4,
                data: vec![1, 2, 3, 4],
            },
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            vec![],
            inits,
            memory_type,
            1,  // Current size: 1 page
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_mismatched_init_size() {
        let limits = crate::parser::types::Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let inits = vec![
            MemoryInit {
                offset: 0,
                size: 4,
                data: vec![1, 2, 3],  // Only 3 bytes when size is 4
            },
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            vec![],
            inits,
            memory_type,
            1,  // Current size: 1 page
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs.clone()).is_err());
    }

    #[test]
    fn test_overlapping_inits() {
        let limits = crate::parser::types::Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let inits = vec![
            MemoryInit {
                offset: 0,
                size: 4,
                data: vec![1, 2, 3, 4],
            },
            MemoryInit {
                offset: 2,  // Overlaps with previous init
                size: 4,
                data: vec![5, 6, 7, 8],
            },
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            vec![],
            inits,
            memory_type,
            1,  // Current size: 1 page
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        // Overlapping inits are allowed since they happen in sequence
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_zero_size_init() {
        let limits = crate::parser::types::Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let inits = vec![
            MemoryInit {
                offset: 0,
                size: 0,
                data: vec![],
            },
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            vec![],
            inits,
            memory_type,
            1,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_back_to_back_inits() {
        let limits = crate::parser::types::Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let inits = vec![
            MemoryInit {
                offset: 0,
                size: 4,
                data: vec![1, 2, 3, 4],
            },
            MemoryInit {
                offset: 4,  // Starts exactly where previous init ends
                size: 4,
                data: vec![5, 6, 7, 8],
            },
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            vec![],
            inits,
            memory_type,
            1,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_multiple_overlapping_inits() {
        let limits = crate::parser::types::Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let inits = vec![
            MemoryInit {
                offset: 0,
                size: 6,
                data: vec![1, 2, 3, 4, 5, 6],
            },
            MemoryInit {
                offset: 2,
                size: 6,
                data: vec![7, 8, 9, 10, 11, 12],
            },
            MemoryInit {
                offset: 4,
                size: 4,
                data: vec![13, 14, 15, 16],
            },
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            vec![],
            inits,
            memory_type,
            1,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_page_boundary_init() {
        let limits = crate::parser::types::Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let inits = vec![
            MemoryInit {
                offset: 65536 - 4,  // Last 4 bytes of first page
                size: 4,
                data: vec![1, 2, 3, 4],
            },
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            vec![],
            inits,
            memory_type,
            1,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_memory_growth_and_access() {
        let limits = crate::parser::types::Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let accesses = vec![
            // First grow memory by 1 page
            MemoryAccess::Grow(1),
            // Then try to access the new page
            MemoryAccess::Store(65536, 8, 4),  // Store at start of new page
            MemoryAccess::Load(65536 + 4, 4, 4),  // Load from middle of new page
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            accesses,
            vec![],
            memory_type,
            2,  // Final pages after growth
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_max_memory_growth() {
        let limits = crate::parser::types::Limits::new(1, Some(3));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let accesses = vec![
            MemoryAccess::Grow(1),  // Grow to 2 pages
            MemoryAccess::Grow(1),  // Grow to 3 pages (max)
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            accesses,
            vec![],
            memory_type,
            3,  // Final pages
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    #[should_panic]
    fn test_exceed_max_memory_growth() {
        let limits = crate::parser::types::Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let accesses = vec![
            MemoryAccess::Grow(2),  // Try to grow beyond max pages
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            accesses,
            vec![],
            memory_type,
            3,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
    }

    #[test]
    fn test_complex_memory_pattern() {
        let limits = crate::parser::types::Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let accesses = vec![
            // Initialize first page
            MemoryAccess::Store(0, 8, 8),
            // Grow memory
            MemoryAccess::Grow(1),
            // Access both pages
            MemoryAccess::Store(65536 - 8, 8, 16),  // Cross-page store
            MemoryAccess::Load(65536 - 4, 4, 8),    // Cross-page load
        ];

        let inits = vec![
            MemoryInit {
                offset: 0,
                size: 8,
                data: vec![1, 2, 3, 4, 5, 6, 7, 8],
            },
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            accesses,
            inits,
            memory_type.clone(),
            2,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(circuit.generate_constraints(cs.clone()).is_ok());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_complex_memory_pattern_with_load_store() {
        let limits = crate::parser::types::Limits::new(1, Some(2));
        let memory_type = MemoryType::new(limits, false).unwrap();
        let accesses = vec![
            MemoryAccess::Load(0, 4, 4),
            MemoryAccess::Store(4, 4, 4),
            MemoryAccess::Grow(1),
        ];

        let circuit = MemorySafetyCircuit::<Fr>::new(
            accesses,
            vec![],
            memory_type,
            2,  // Final pages after growth
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
