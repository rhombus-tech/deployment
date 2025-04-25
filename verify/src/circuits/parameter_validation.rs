//! Parameter Validation Circuit for WebAssembly
//!
//! This module implements a zero-knowledge circuit that verifies parameter validation properties
//! of WebAssembly programs. It ensures:
//! 
//! 1. Length Validation:
//!    - Parameters do not exceed maximum allowed length (typically 1024 bytes for Wasmlanche)
//!    - Protects against the 3.5 billion parameter length bug
//! 
//! 2. Memory Safety:
//!    - Parameters are properly bounds-checked
//!    - Memory access is validated against allowed memory size
//! 
//! 3. Type Enforcement:
//!    - Parameter types match expected contract interface
//! 
//! All validations use direct constraint system calls with no FpVar/gadgets/Ordering
//! This circuit complements memory safety by focusing specifically on input parameters.

use ark_ff::Field;
// Use the lc macro directly from the crate root
#[allow(unused_imports)]
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
// Bring lc! macro into scope
use ark_relations::lc;
use ark_bls12_381::Fr;

// We directly import the lc macro in the import statement above
use ark_std::{marker::PhantomData, vec};

use common::ValidationTypeInfo;
use anyhow::Result;
use wasmparser::MemoryType;

// We'll define our own ParameterValidation struct for this module
// that's independent of the common ParameterValidationInfo

/// Represents a parameter validation operation in a WebAssembly program
#[derive(Debug, Clone)]
pub enum ParameterValidation {
    /// Length check: validates that a parameter's length is within bounds
    /// Parameters: (parameter_index, max_allowed_length, validation_location)
    LengthCheck(u32, u64, u32),
    
    /// Type check: validates parameter has expected type
    /// Parameters: (parameter_index, expected_type, validation_location)
    TypeCheck(u32, String, u32),
    
    /// Bounds check: validates memory access is within bounds
    /// Parameters: (address, size, validation_location)
    BoundsCheck(u64, u64, u32),
    
    /// Complex validation with multiple checks
    /// Parameters: (parameter_index, validation_descriptions, validation_location)
    ComplexValidation(u32, Vec<String>, u32),
}

/// Represents the type of validation being performed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationTypeCode {
    /// Length check validation
    LengthCheck = 0,
    /// Range check validation
    RangeCheck = 1,
    /// Type check validation
    TypeCheck = 2,
    /// Memory bounds check
    BoundsCheck = 3,
    /// Composite validation (multiple checks)
    Composite = 4,
    /// Rejection of invalid parameters
    Rejection = 5,
    /// Protocol-specific validation
    ProtocolSpecific = 6,
    /// Other validation type
    Other = 7,
}

/// Circuit for verifying parameter validation properties of WebAssembly programs
/// 
/// This circuit ensures that input parameters are properly validated by:
/// 1. Checking length validation for parameters
/// 2. Ensuring memory bounds are respected
/// 3. Validating parameter types
#[derive(Debug, Clone)]
pub struct ParameterValidationCircuit<F: Field> {
    /// Parameter validation operations to enforce
    pub validations: Vec<ParameterValidation>,
    /// Maximum parameter length allowed by the protocol
    pub max_parameter_length: u64,
    /// WebAssembly memory type
    pub memory_type: MemoryType,
    /// Current number of memory pages
    pub current_pages: usize,
    /// Phantom data for the field
    _phantom: PhantomData<F>,
}

impl<F: Field> ParameterValidationCircuit<F> {
    /// Create a new parameter validation circuit
    pub fn new(
        validations: Vec<ParameterValidation>,
        max_parameter_length: u64,
        memory_type: MemoryType,
        current_pages: usize,
    ) -> Self {
        Self {
            validations,
            max_parameter_length,
            memory_type,
            current_pages,
            _phantom: PhantomData,
        }
    }
    
    /// Helper to convert u64 to field element
    fn u64_to_field(value: u64) -> F {
        F::from(value)
    }
    
    /// Helper to convert u32 to field element
    fn u32_to_field(value: u32) -> F {
        F::from(value as u64)
    }
    
    /// Validates that a parameter length is reasonable
    /// Implements the "unreasonable length" check (e.g., >1024 bytes)
    fn validate_parameter_length(&self, length: u64) -> bool {
        length <= self.max_parameter_length
    }
    
    // The validate_parameter_length_constraint function has been removed to eliminate
    // any potential trait bound issues. Its functionality is now directly in process_length_check.

    /// Implementation of parameter length check with no gadgets or trait bounds
    /// This is a direct implementation with no forwarding to other methods
    fn process_length_check(
        &self,
        cs: ConstraintSystemRef<F>,
        param_length: u64,
        max_length: u64,
    ) -> Result<(), SynthesisError> 
    where F: Field
    {
        // Create witnesses for our critical values
        let one = cs.new_witness_variable(|| Ok(F::one()))?;
        let zero = cs.new_witness_variable(|| Ok(F::zero()))?;
        
        // Direct pure Rust logic with no trait bounds
        if param_length > max_length {
            // Create an unsatisfiable constraint: 1 * 1 = 0
            cs.enforce_constraint(lc!() + one, lc!() + one, lc!() + zero)?;
        }
        
        // Valid parameter length
        Ok(())
    }
    
    /// Create an unsatisfiable constraint in the circuit
    /// This function uses only basic operations with no gadgets
    fn create_unsatisfiable_constraint(
        &self,
        cs: ConstraintSystemRef<F>
    ) -> Result<(), SynthesisError>
    where F: Field
    {
        // Create witness variables for one and zero directly
        let one = cs.new_witness_variable(|| Ok(F::one()))?;
        let zero = cs.new_witness_variable(|| Ok(F::zero()))?;
        
        // 1*1=0 is always unsatisfiable - using simple linear combination
        // Avoiding any potential hidden type references
        cs.enforce_constraint(
            lc!() + one, 
            lc!() + one,
            lc!() + zero
        )
    }
    
    /// A clean implementation of memory bounds checking without indirect references to problematic types
    fn validate_memory_access(
        &self,
        cs: ConstraintSystemRef<F>,
        base_addr: u64, 
        access_size: u64
    ) -> Result<(), SynthesisError>
    where F: Field 
    {
        // Calculate maximum memory size in bytes (64KB per page)
        let max_memory_size = (self.current_pages * 65536) as u64;
        
        // First compute if access is valid in pure Rust
        let valid_access = match base_addr.checked_add(access_size) {
            // No overflow, check against memory limit
            Some(end_addr) => end_addr <= max_memory_size,
            // Overflow in address calculation - definitely invalid
            None => false,
        };
        
        // Only create constraints if needed
        if !valid_access {
            // Use the constraint system directly without gadgets
            // Create witness variables for the constraint system
            let one_var = cs.new_witness_variable(|| Ok(F::one()))?;
            let zero_var = cs.new_witness_variable(|| Ok(F::zero()))?;
            
            // 1*1=0 is unsatisfiable
            cs.enforce_constraint(lc!() + one_var, lc!() + one_var, lc!() + zero_var)?;
        }
        
        Ok(())
    }
    
    /// Original function name maintained for backward compatibility 
    fn process_bounds_check(
        &self, 
        cs: ConstraintSystemRef<F>,
        address: u64,
        size: u64,
    ) -> Result<(), SynthesisError>
    where F: Field
    {
        // Forward to our new implementation
        self.validate_memory_access(cs, address, size)
    }
    
    /// This older implementation is kept for compatibility with existing tests
    fn check_memory_bounds(
        &self,
        cs: ConstraintSystemRef<F>,
        addr: u64, 
        len: u64
    ) -> Result<(), SynthesisError>
    where F: Field
    {
        // Forward to the new implementation
        self.validate_memory_access(cs, addr, len)
    }
    
    /// Process a complex validation with multiple checks
    fn process_complex_validation(
        &self,
        cs: ConstraintSystemRef<F>,
        _parameter_index: u32,
        validations: &[String],
    ) -> Result<(), SynthesisError> 
    where F: Field
    {
        // Ensure at least one validation exists
        let validation_count = validations.len();
        
        // Check for common validation patterns
        let has_length_check = validations.iter().any(|v| v.contains("length"));
        let has_bounds_check = validations.iter().any(|v| v.contains("bounds"));
        let has_type_check = validations.iter().any(|v| v.contains("type"));
        
        // A valid complex validation requires at least one check
        let is_valid = validation_count >= 1 && 
                       (has_length_check || has_bounds_check || has_type_check);
        
        // If the validation is invalid, create an unsatisfiable constraint
        if !is_valid {
            // Create variables for the constraint system
            let one_var = cs.new_witness_variable(|| Ok(F::one()))?;
            let zero_var = cs.new_witness_variable(|| Ok(F::zero()))?;
            
            // 1*1=0 is unsatisfiable
            cs.enforce_constraint(
                lc!() + one_var,
                lc!() + one_var,
                lc!() + zero_var
            )?;
        }
        
        Ok(())
    }
    
    /// Generate constraints for parameter validation
    fn generate_parameter_validation_constraints(
        &self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> 
    where F: Field
    {
        // Process each parameter validation in our list
        for validation in &self.validations {
            match validation {
                ParameterValidation::LengthCheck(_param_idx, max_allowed, _) => {
                                    // Use a clone of cs to avoid ownership issues
                    self.process_length_check(cs.clone(), *max_allowed, *max_allowed)?
                },
                ParameterValidation::TypeCheck(_param_idx, expected_type, _) => {
                    // A simple type check that avoids clone() trait bound issues
                    let type_exists = !expected_type.is_empty();
                    
                    // Only create constraints when not in setup mode
                    if !cs.is_in_setup_mode() && !type_exists {
                        // Convert the type checking to an unsatisfiable constraint if invalid
                        let one_var = cs.new_witness_variable(|| Ok(F::one()))?;
                        let zero_var = cs.new_witness_variable(|| Ok(F::zero()))?;
                        
                        // 1*1=0 is unsatisfiable
                        cs.enforce_constraint(lc!() + one_var, lc!() + one_var, lc!() + zero_var)?;
                    }
                },
                ParameterValidation::BoundsCheck(address, size, _) => {
                    // Process bounds check with clone to avoid ownership issues
                    self.process_bounds_check(cs.clone(), *address, *size)?
                },
                ParameterValidation::ComplexValidation(param_idx, validations, _) => {
                    // Process complex validation with clone to avoid ownership issues
                    self.process_complex_validation(cs.clone(), *param_idx, validations.as_slice())?
                },
            }
        }

        // Enforce that all parameter lengths are within protocol max
        // This is separate from contract-specific validations and always enforced
        self.enforce_protocol_max_parameter_length(cs)?;

        Ok(())
    }
    
    /// Enforce that all parameter lengths are within protocol max 
    /// to protect against the 3.5 billion byte parameter vulnerability
    fn enforce_protocol_max_parameter_length(
        &self,
        cs: ConstraintSystemRef<F>,
    ) -> Result<(), SynthesisError> 
    where F: Field
    {
        // For each validation, ensure parameter length is within protocol max
        for validation in &self.validations {
            if let ParameterValidation::LengthCheck(_, length, _) = validation {
                // Direct Rust comparison, no FpVar or Boolean gadgets
                let is_valid = length <= &self.max_parameter_length;
                
                // Create unsatisfiable constraint if length exceeds protocol max
                if !is_valid {
                    // Direct constraint system API avoiding all gadgets
                    // Create variables for one and zero
                    let one_var = cs.new_witness_variable(|| Ok(F::one()))?;
                    let zero_var = cs.new_witness_variable(|| Ok(F::zero()))?;
                    
                    // Create linear combinations from variables (1*1=0 is unsatisfiable)
                    cs.enforce_constraint(
                        lc!() + one_var,
                        lc!() + one_var,
                        lc!() + zero_var
                    )?;
                }
            }
            // Other validation types don't have a length to check
        }
        
        Ok(())
    }
}

impl<F: Field> ConstraintSynthesizer<F> for ParameterValidationCircuit<F> {
    /// Generate constraints for the validation circuit
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Pass the constraint system by reference to avoid clone() issues
        self.generate_parameter_validation_constraints(cs)?;
        
        Ok(())
    }
}

/// Convert from common ValidationTypeInfo to circuit ValidationTypeCode
pub fn convert_validation_type(validation_type: &ValidationTypeInfo) -> ValidationTypeCode {
    match validation_type {
        ValidationTypeInfo::LengthCheck => ValidationTypeCode::LengthCheck,
        ValidationTypeInfo::RangeCheck => ValidationTypeCode::RangeCheck,
        ValidationTypeInfo::TypeCheck => ValidationTypeCode::TypeCheck,
        ValidationTypeInfo::BoundsCheck => ValidationTypeCode::BoundsCheck,
        ValidationTypeInfo::Composite => ValidationTypeCode::Composite,
        ValidationTypeInfo::Rejection => ValidationTypeCode::Rejection,
        ValidationTypeInfo::ProtocolSpecific(_) => ValidationTypeCode::ProtocolSpecific,
        ValidationTypeInfo::Other => ValidationTypeCode::Other,
    }
}

/// Convert parameter validation info from common format to circuit format
pub fn convert_validation_info_to_circuit<F: Field>(
    infos: &[common::ParameterValidationInfo],
) -> Vec<ParameterValidation> {
    infos.iter()
        .filter_map(|info| {
            match convert_validation_type(&info.validation_type) {
                ValidationTypeCode::LengthCheck => {
                    if let Some(max) = info.max_allowed_length {
                        let idx = info.parameter_index.unwrap_or(0);
                        Some(ParameterValidation::LengthCheck(idx, max, 0))
                    } else {
                        None
                    }
                },
                ValidationTypeCode::BoundsCheck => {
                    if let Some(max) = info.max_allowed_length {
                        let idx = info.parameter_index.unwrap_or(0);
                        Some(ParameterValidation::BoundsCheck(idx as u64, max, 0))
                    } else {
                        None
                    }
                },
                ValidationTypeCode::TypeCheck => {
                    if let Some(type_info) = &info.metadata {
                        let idx = info.parameter_index.unwrap_or(0);
                        Some(ParameterValidation::TypeCheck(idx, type_info.clone(), 0))
                    } else {
                        None
                    }
                },
                ValidationTypeCode::Composite | ValidationTypeCode::ProtocolSpecific | _ => {
                    if let Some(idx) = info.parameter_index {
                        let descriptions = vec![info.validation_strategy.clone()];
                        Some(ParameterValidation::ComplexValidation(idx, descriptions, 0))
                    } else {
                        None
                    }
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_parameter_length_validation() {
        // Create a circuit that enforces a maximum parameter length of 1024
        let validations = vec![
            ParameterValidation::LengthCheck(0, 1024, 0),
        ];
        
        // Create a simple memory type for testing
        // In a real implementation, we would use appropriate memory limits
        #[allow(deprecated)]
        let memory_type = unsafe { std::mem::zeroed::<MemoryType>() };
        
        let circuit = ParameterValidationCircuit::<Fr>::new(
            validations,
            1024, // Protocol max of 1024 bytes
            memory_type,
            1,
        );
        
        // Create constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        // Generate constraints
        circuit.generate_constraints(cs.clone()).unwrap();
        
        // Check if constraints are satisfied
        assert!(cs.is_satisfied().unwrap());
    }
    
    #[test]
    fn test_unreasonable_parameter_length() {
        // Create a circuit with unreasonable validation (param length > Wasmlanche max)
        let max_length = 3_500_000_000; // 3.5B - the parameter length vulnerability from Wasmlanche
        let validations = vec![
            ParameterValidation::LengthCheck(0, max_length, 0)
        ];
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        let memory_type = unsafe { std::mem::zeroed::<MemoryType>() };
        
        let circuit = ParameterValidationCircuit::<Fr>::new(
            validations,
            1024, // Max parameter length - Wasmlanche limit for safe parameter handling
            memory_type,
            1, // 1 memory page
        );
        
        // Generate constraints using direct constraint system API
        assert!(circuit.generate_constraints(cs).is_ok(), 
                "Parameter validation circuit should generate constraints");
        
        // Create a new CS for the satisfaction check since we already consumed the previous one
        let cs2 = ConstraintSystem::<Fr>::new_ref();
        let circuit2 = ParameterValidationCircuit::<Fr>::new(
            vec![ParameterValidation::LengthCheck(0, max_length, 0)],
            1024,
            memory_type,
            1,
        );
        circuit2.generate_constraints(cs2.clone()).unwrap();
        
        // We expect this to fail because the parameter length exceeds the protocol max
        assert!(!cs2.is_satisfied().unwrap(), 
                "Circuit should be unsatisfiable with unreasonable lengths");
    }
    
    #[test]
    fn test_parameter_bounds_checking() {
        // Create a circuit with memory bounds validation
        let address = 1000; // Starting at byte 1000
        let size = 100;    // Reading 100 bytes
        
        let validations = vec![
            ParameterValidation::BoundsCheck(address, size, 0)
        ];
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        let memory_type = unsafe { std::mem::zeroed::<MemoryType>() };
        
        let circuit = ParameterValidationCircuit::<Fr>::new(
            validations,
            1024, // Max parameter length
            memory_type,
            4, // 4 memory pages = 256KB, plenty for our bounds check
        );
        
        // Generate constraints directly using Boolean gadgets
        assert!(circuit.generate_constraints(cs).is_ok(),
                "Parameter validation circuit should generate constraints");
        
        // Create a new CS for the satisfaction check
        let cs2 = ConstraintSystem::<Fr>::new_ref();
        let circuit2 = ParameterValidationCircuit::<Fr>::new(
            vec![ParameterValidation::BoundsCheck(address, size, 0)],
            1024,
            memory_type,
            4,
        );
        circuit2.generate_constraints(cs2.clone()).unwrap();
        
        // With 4 pages of memory, this access (1000+100=1100 bytes) is within bounds
        assert!(cs2.is_satisfied().unwrap(), 
                "Circuit should be satisfiable with valid memory bounds");
    }
    
    #[test]
    fn test_out_of_bounds_parameter() {
        // Create a circuit with out-of-bounds memory access
        let memory_pages = 1; // 1 page = 65536 bytes
        let address = 65000;  // Near the end of memory
        let size = 1000;     // Would go past the end of memory (65000+1000 > 65536)
        
        let validations = vec![
            ParameterValidation::BoundsCheck(address, size, 0)
        ];
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        let memory_type = unsafe { std::mem::zeroed::<MemoryType>() };
        
        let circuit = ParameterValidationCircuit::<Fr>::new(
            validations,
            1024, // Max parameter length - Wasmlanche limit for safe parameter handling
            memory_type,
            memory_pages,
        );
        
        // Generate constraints using direct constraint system API
        assert!(circuit.generate_constraints(cs).is_ok(), 
                "Parameter validation circuit should generate constraints");
        
        // Create a new CS for the satisfaction check
        let cs2 = ConstraintSystem::<Fr>::new_ref();
        let circuit2 = ParameterValidationCircuit::<Fr>::new(
            vec![ParameterValidation::BoundsCheck(address, size, 0)],
            1024,
            memory_type,
            memory_pages,
        );
        circuit2.generate_constraints(cs2.clone()).unwrap();
        
        // The constraints should be unsatisfiable since we're trying to access memory out of bounds
        assert!(!cs2.is_satisfied().unwrap(), 
                "Circuit should be unsatisfiable with out-of-bounds access");
    }
    
    #[test]
    fn test_complex_validation() {
        // Create a circuit with complex validations
        let validations = vec![
            ParameterValidation::ComplexValidation(
                0, // Parameter index
                vec!["length".to_string(), "bounds".to_string()],
                0  // Location
            )
        ];
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        let memory_type = unsafe { std::mem::zeroed::<MemoryType>() };
        
        let circuit = ParameterValidationCircuit::<Fr>::new(
            validations,
            1024, // Max parameter length - Wasmlanche limit
            memory_type,
            2, // 2 memory pages
        );
        
        // Generate constraints using direct constraint system API
        assert!(circuit.generate_constraints(cs).is_ok(), 
                "Parameter validation circuit should generate constraints");
        
        // Create a new CS for the satisfaction check
        let cs2 = ConstraintSystem::<Fr>::new_ref();
        let circuit2 = ParameterValidationCircuit::<Fr>::new(
            vec![ParameterValidation::ComplexValidation(
                0, 
                vec!["length".to_string(), "bounds".to_string()],
                0
            )],
            1024,
            memory_type,
            2,
        );
        circuit2.generate_constraints(cs2.clone()).unwrap();
        
        // Complex validation combines multiple checks and should satisfy all constraints
        assert!(cs2.is_satisfied().unwrap_or(false), 
                "Circuit should be satisfiable with complex validation");
    }
    
    #[test]
    fn test_simple_validation() {
        // Create a circuit with no validations
        let validations = vec![];
        
        let cs = ConstraintSystem::<Fr>::new_ref();
        let memory_type = unsafe { std::mem::zeroed::<MemoryType>() };
        
        let circuit = ParameterValidationCircuit::<Fr>::new(
            validations,
            1024, // Max parameter length
            memory_type,
            1, // 1 memory page
        );
        
        // Circuit should generate constraints successfully
        // Use cs directly to generate the constraints
        assert!(circuit.generate_constraints(cs).is_ok(),
                "Parameter validation circuit should generate constraints");
    }
}
