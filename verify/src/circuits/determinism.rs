//! Determinism Validation Circuit for WebAssembly
//!
//! This module implements a zero-knowledge circuit that verifies deterministic
//! execution properties of WebAssembly programs. It ensures:
//!
//! 1. No Floating Point Operations:
//!    - Floating point operations can lead to different results across platforms
//!    - Different rounding modes or precision can cause inconsistencies
//!
//! 2. No Time-Dependent Operations:
//!    - Time-based functions lead to non-deterministic execution
//!    - Clock or timestamp access breaks consistency between TEEs
//!
//! 3. No Random Number Generation:
//!    - Random number generators produce different results on each execution
//!    - PRNG initialization might differ between TEEs
//!
//! 4. No Environment Access:
//!    - Environment variables or system properties may differ between TEEs
//!    - File system or network access leads to inconsistent state
//!
//! 5. No Hardware-Dependent Operations:
//!    - CPU-specific instructions or optimizations
//!    - SIMD operations that may behave differently on different hardware

use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, Variable};
use ark_std::marker::PhantomData;
use walrus::Module;
use ark_relations::lc;
use anyhow::Result;
use std::fmt;

/// Types of non-deterministic operations that can break determinism
#[derive(Debug, Clone, PartialEq)]
pub enum NonDeterministicOperation {
    /// Floating point operations that can have different precision on different platforms
    FloatingPoint(String),
    /// Time-dependent operations that rely on system clock or timestamps
    TimeDependent(String),
    /// Random number generation operations
    RandomNumberGeneration(String),
    /// Operations that access environment variables or system properties
    EnvironmentAccess(String),
    /// Operations that depend on specific hardware features or optimizations
    HardwareDependent(String),
}

impl fmt::Display for NonDeterministicOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NonDeterministicOperation::FloatingPoint(desc) => write!(f, "Floating Point: {}", desc),
            NonDeterministicOperation::TimeDependent(desc) => write!(f, "Time Dependent: {}", desc),
            NonDeterministicOperation::RandomNumberGeneration(desc) => write!(f, "Random Number Generation: {}", desc),
            NonDeterministicOperation::EnvironmentAccess(desc) => write!(f, "Environment Access: {}", desc),
            NonDeterministicOperation::HardwareDependent(desc) => write!(f, "Hardware Dependent: {}", desc),
        }
    }
}

/// The circuit for verifying deterministic execution
pub struct DeterminismCircuit<F: Field> {
    /// WebAssembly module to analyze
    pub module: Module,
    /// Non-deterministic operations found in the module
    pub operations: Vec<NonDeterministicOperation>,
    /// Whether non-deterministic operations were detected
    pub has_non_deterministic_ops: bool,
    /// Test mode flag - when enabled, validation can be bypassed
    pub test_mode: bool,
    /// Phantom data for the field
    pub _phantom: PhantomData<F>,
}

impl<F: Field> DeterminismCircuit<F> {
    /// Create a new determinism verification circuit
    pub fn new(module: Module) -> Self {
        let operations = analyze_determinism(&module);
        let has_non_deterministic_ops = !operations.is_empty();
        
        Self {
            module,
            operations,
            has_non_deterministic_ops,
            test_mode: false,
            _phantom: PhantomData,
        }
    }
    
    /// Create a new determinism verification circuit with provided operations (for testing)
    pub fn new_with_operations(operations: Vec<NonDeterministicOperation>, test_mode: bool) -> Self {
        // Create a dummy empty module for testing
        let module = Module::default();
        let has_non_deterministic_ops = !operations.is_empty();
        
        Self {
            module,
            operations,
            has_non_deterministic_ops,
            test_mode,
            _phantom: PhantomData,
        }
    }
    
    /// Helper method to convert a u32 to field element
    fn u32_to_field(value: u32) -> F {
        let mut result = F::zero();
        let mut base = F::one();
        let two = base.clone() + base.clone();
        
        // Convert base 2 to field element
        for i in 0..32 {
            if (value >> i) & 1 == 1 {
                result += base.clone();
            }
            base *= two.clone();
        }
        
        result
    }
    
    /// Set test mode for the circuit
    /// 
    /// When test mode is enabled, validation can be bypassed for testing purposes.
    /// This is useful for running tests with code that would normally fail validation.
    pub fn set_test_mode(&mut self, enabled: bool) -> &mut Self {
        self.test_mode = enabled;
        self
    }
    
    /// Check if test mode is enabled
    pub fn is_test_mode(&self) -> bool {
        self.test_mode
    }
    
    /// Convert a boolean to a field element
    fn bool_to_field(b: bool) -> F {
        if b {
            F::one()
        } else {
            F::zero()
        }
    }
}

impl<F: Field> ConstraintSynthesizer<F> for DeterminismCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // Convert the boolean to a field element (0 or 1)
        let has_non_deterministic_ops_value = if self.has_non_deterministic_ops {
            F::one()
        } else {
            F::zero()
        };
        
        // Create a witness variable for whether non-deterministic operations exist
        let has_non_deterministic_ops_var = cs.new_witness_variable(
            || Ok(has_non_deterministic_ops_value)
        )?;
        
        // If test mode is enabled, we skip the constraints
        if !self.test_mode {
            // Constrain that there are no non-deterministic operations
            // Enforce: has_non_deterministic_ops * 1 = 0
            // This will cause the constraint system to be unsatisfiable if has_non_deterministic_ops = 1
            cs.enforce_constraint(
                lc!() + has_non_deterministic_ops_var,
                lc!() + Variable::One,
                lc!()
            )?;
            
            // Print information about failed constraints in debug mode
            #[cfg(debug_assertions)]
            if self.has_non_deterministic_ops {
                println!("Determinism validation failed due to:");
                for op in &self.operations {
                    println!("  - {}", op);
                }
            }
        } else {
            // In test mode, we simply log that validation was bypassed
            #[cfg(debug_assertions)]
            if self.has_non_deterministic_ops {
                println!("WARNING: Determinism validation bypassed due to test mode");
                println!("The following non-deterministic operations were detected but ignored:");
                for op in &self.operations {
                    println!("  - {}", op);
                }
            }
        }
        
        Ok(())
    }
}

/// Analyze a WebAssembly module for non-deterministic operations
pub fn analyze_determinism(module: &Module) -> Vec<NonDeterministicOperation> {
    analyze_determinism_with_options(module, false)
}

/// Analyze a WebAssembly module for non-deterministic operations with options
pub fn analyze_determinism_with_options(module: &Module, _test_mode: bool) -> Vec<NonDeterministicOperation> {
    let mut operations = Vec::new();
    
    // Always run all checks, as we want to detect all non-deterministic operations
    // regardless of whether we're in test mode or not
    
    // 1. Check for floating point operations
    detect_floating_point_ops(module, &mut operations);
    
    // 2. Check for time-dependent imports
    detect_time_dependent_imports(module, &mut operations);
    
    // 3. Check for random number generation
    detect_random_number_generation(module, &mut operations);
    
    // 4. Check for environment access
    detect_environment_access(module, &mut operations);
    
    // 5. Check for hardware-dependent operations
    detect_hardware_dependent_ops(module, &mut operations);
    
    // Note: The test_mode flag is still used in the DeterminismCircuit to bypass
    // constraint enforcement when needed, but we still detect all issues here
    
    operations
}

/// Check for floating point operations in the module
fn detect_floating_point_ops(module: &Module, operations: &mut Vec<NonDeterministicOperation>) {
    let fp_markers = [
        "f32", "f64", 
        "Float32", "Float64", 
        "Nearest", "Ceil", "Floor", "Trunc",
        "Abs", "Neg", "Sqrt", "Min", "Max",
        "Copysign",
    ];
    
    for func in module.funcs.iter() {
        // Only check functions that have a defined body (not imports)
        if let walrus::FunctionKind::Local(local_func) = &func.kind {
            // Create a function name string for the error message
            let function_name = if let Some(name) = &func.name {
                name.clone()
            } else {
                format!("func_{}", func.id().index())
            };
            
            // Get the function body
            let entry_block_id = local_func.entry_block();
            let block = local_func.block(entry_block_id);
            
            // Iterate through all instructions in the function
            for (instr, _loc_id) in &block.instrs {
                // Get a debug string representation of the instruction
                let instr_debug = format!("{:?}", instr);
                
                // Check if the instruction string contains floating point operation markers
                // Use case-insensitive comparison since the debug output may have mixed case
                let is_floating_point = fp_markers.iter().any(|&marker| 
                    instr_debug.to_lowercase().contains(&marker.to_lowercase())
                );
                
                if is_floating_point {
                    operations.push(NonDeterministicOperation::FloatingPoint(
                        format!("{} in function {}", instr_debug, function_name)
                    ));
                }
            }
        }
    }
}

/// Check for time-dependent imports that could break determinism
fn detect_time_dependent_imports(module: &Module, operations: &mut Vec<NonDeterministicOperation>) {
    let time_related_names = [
        "time", "date", "clock", "now", "timestamp", 
        "getTime", "getDate", "getDay", "getHours", "getMinutes", "getSeconds",
        "performance", "sys_time", "current_time", "block_time", "cycle",
        "rdtsc", "timer", "timeout", "interval"
    ];
    
    for import in module.imports.iter() {
        // Get the import name and module as strings
        // Access the name and module directly as strings
        let name: &str = import.name.as_str();
        let module_name: &str = import.module.as_str();
        
        // Check if this import name suggests time-related functionality
        let is_time_related = time_related_names.iter()
            .any(|&time_name| {
                name.to_lowercase().contains(&time_name.to_lowercase()) || 
                module_name.to_lowercase().contains(&time_name.to_lowercase())
            });
        
        if is_time_related {
            operations.push(NonDeterministicOperation::TimeDependent(
                format!("Import {}.{}", module_name, name)
            ));
        }
    }
}

/// Check for random number generation imports or patterns
fn detect_random_number_generation(module: &Module, operations: &mut Vec<NonDeterministicOperation>) {
    let rng_related_names = [
        "random", "rand", "rng", 
        "uuid", "guid", 
        "crypto", "randombytes",
    ];
    
    // Check imports for RNG functionality
    for import in module.imports.iter() {
        // Get the import name and module as strings
        // Access the name and module directly as strings
        let name: &str = import.name.as_str();
        let module_name: &str = import.module.as_str();
        
        // Check if this import name suggests random number generation
        let is_rng_related = rng_related_names.iter()
            .any(|&rng_name| name.to_lowercase().contains(&rng_name.to_lowercase()));
        
        if is_rng_related {
            operations.push(NonDeterministicOperation::RandomNumberGeneration(
                format!("Import {}.{}", module_name, name)
            ));
        }
    }
    
    // Could add more sophisticated checks for RNG algorithm implementations
    // but that would require more complex static analysis
}

/// Check for environment access that could differ between TEEs
fn detect_environment_access(module: &Module, operations: &mut Vec<NonDeterministicOperation>) {
    let env_markers = [
        "env", "environment", "getenv", 
        "filesystem", "file", "open", "read", "write",
        "network", "socket", "connect", "http", "https",
    ];
    let fs_markers = [
        "file", "open", "read", "write",
    ];
    
    // Check imports for environment access
    for import in module.imports.iter() {
        // Get the import name and module as strings
        // Access the name and module directly as strings
        let name: &str = import.name.as_str();
        let module_name: &str = import.module.as_str();
        
        // Check for environment variable access
        let is_env_var_access = env_markers.iter()
            .any(|&marker| name.to_lowercase().contains(&marker.to_lowercase()));
        
        if is_env_var_access {
            operations.push(NonDeterministicOperation::EnvironmentAccess(
                format!("Environment access via {}.{}", module_name, name)
            ));
        }
        
        // Check for file system access
        let is_file_access = fs_markers.iter()
            .any(|&marker| name.to_lowercase().contains(&marker.to_lowercase()));
        
        if is_file_access {
            operations.push(NonDeterministicOperation::EnvironmentAccess(
                format!("File system access via {}.{}", module_name, name)
            ));
        }
    }
}

/// Check for hardware-dependent operations that could differ between TEEs
fn detect_hardware_dependent_ops(module: &Module, operations: &mut Vec<NonDeterministicOperation>) {
    let hw_markers = [
        "simd", "vector", "atomic", 
        "cpu", "processor", "core",
        "sse", "avx", "neon", "sve", // SIMD extensions
        "gpu", "opencl", "cuda", // GPU acceleration
    ];
    
    // Check imports for hardware-specific functionality
    for import in module.imports.iter() {
        // Get the import name and module as strings
        // Access the name and module directly as strings
        let name: &str = import.name.as_str();
        let module_name: &str = import.module.as_str();
        
        // Check for SIMD or other hardware-specific operations
        let is_hardware_dependent = hw_markers.iter()
            .any(|&marker| 
                name.to_lowercase().contains(&marker.to_lowercase()) ||
                module_name.to_lowercase().contains(&marker.to_lowercase())
            );
        
        if is_hardware_dependent {
            operations.push(NonDeterministicOperation::HardwareDependent(
                format!("Hardware-dependent operation via {}.{}", module_name, name)
            ));
        }
    }
    
    // Check for SIMD instructions in the code
    for func in module.funcs.iter() {
        if let walrus::FunctionKind::Local(local_func) = &func.kind {
            // Create a function name string for the error message
            let function_name = if let Some(name) = &func.name {
                name.clone()
            } else {
                format!("func_{}", func.id().index())
            };
            
            let entry_block_id = local_func.entry_block();
            let block = local_func.block(entry_block_id);
            
            for (instr, _loc_id) in &block.instrs {
                let instr_debug = format!("{:?}", instr);
                
                // Check for SIMD instructions
                if instr_debug.contains("simd") || instr_debug.contains("v128") {
                    operations.push(NonDeterministicOperation::HardwareDependent(
                        format!("SIMD instruction in function {}: {}", function_name, instr_debug)
                    ));
                }
                
                // Check for atomic operations
                if instr_debug.contains("atomic") {
                    operations.push(NonDeterministicOperation::HardwareDependent(
                        format!("Atomic instruction in function {}: {}", function_name, instr_debug)
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;
    use ark_relations::r1cs::ConstraintSystem;
    use wat::parse_str;
    
    #[test]
    fn test_detect_floating_point() -> Result<()> {
        // Create a WebAssembly module with floating point operations
        let wat = r#"
            (module
                (func $float_ops (param f32 f32) (result f32)
                    local.get 0
                    local.get 1
                    f32.add
                )
                (export "float_ops" (func $float_ops))
            )
        "#;
        
        let wasm = parse_str(wat)?;
        let module = Module::from_buffer(&wasm)?;
        
        let operations = analyze_determinism(&module);
        
        assert!(!operations.is_empty(), "Should detect floating point operations");
        assert!(
            operations.iter().any(|op| 
                matches!(op, NonDeterministicOperation::FloatingPoint(_))
            ),
            "Should include FloatingPoint operation type"
        );
        
        Ok(())
    }
    
    #[test]
    fn test_detect_time_dependent() -> Result<()> {
        // Create a WebAssembly module with time imports
        let wat = r#"
            (module
                (import "env" "get_time" (func $get_time (result i64)))
                (func $current_time (result i64)
                    call $get_time
                )
                (export "current_time" (func $current_time))
            )
        "#;
        
        let wasm = parse_str(wat)?;
        let module = Module::from_buffer(&wasm)?;
        
        let operations = analyze_determinism(&module);
        
        assert!(!operations.is_empty(), "Should detect time dependent operations");
        assert!(
            operations.iter().any(|op| 
                matches!(op, NonDeterministicOperation::TimeDependent(_))
            ),
            "Should include TimeDependent operation type"
        );
        
        Ok(())
    }
    
    #[test]
    fn test_analyze_determinism_with_options() -> Result<()> {
        // Create a module with both floating point and time dependent imports
        let wat = r#"
            (module
                (import "env" "get_time" (func $get_time (result i64)))
                (func $float_ops (param f32 f32) (result f32)
                    local.get 0
                    local.get 1
                    f32.add
                )
                (func $current_time (result i64)
                    call $get_time
                )
                (export "float_ops" (func $float_ops))
                (export "current_time" (func $current_time))
            )
        "#;
        
        let wasm = parse_str(wat)?;
        let module = Module::from_buffer(&wasm)?;
        
        // Debug: Directly check instructions in the module to see floating point ops
        println!("\nDEBUG: Checking module for floating point operations:");
        let mut found_fp_op = false;
        let fp_markers = [
            "f32", "f64", 
            "Float32", "Float64", 
            "Nearest", "Ceil", "Floor", "Trunc",
            "Abs", "Neg", "Sqrt", "Min", "Max",
            "Copysign",
        ];
        
        for func in module.funcs.iter() {
            if let walrus::FunctionKind::Local(local_func) = &func.kind {
                println!("  Function: {}", if let Some(name) = &func.name {
                    name.clone()
                } else {
                    format!("func_{}", func.id().index())
                });
                
                let entry_block_id = local_func.entry_block();
                let block = local_func.block(entry_block_id);
                
                for (instr, _loc_id) in &block.instrs {
                    let instr_debug = format!("{:?}", instr);
                    println!("    Instruction: {}", instr_debug);
                    
                    let is_floating_point = fp_markers.iter().any(|&marker| 
                        instr_debug.to_lowercase().contains(&marker.to_lowercase())
                    );
                    println!("      Contains FP marker: {}", is_floating_point);
                    if is_floating_point {
                        found_fp_op = true;
                    }
                }
            }
        }
        println!("Found floating point operation: {}", found_fp_op);
        
        // Run in normal mode (test_mode = false)
        let normal_ops = analyze_determinism_with_options(&module, false);
        println!("Normal ops: {:#?}", normal_ops);
        
        // Run in test mode (test_mode = true)
        let test_ops = analyze_determinism_with_options(&module, true);
        println!("Test ops: {:#?}", test_ops);
        
        // Verify both modes detect floating point operations
        assert!(
            normal_ops.iter().any(|op| matches!(op, NonDeterministicOperation::FloatingPoint(_))),
            "Normal mode should detect floating point operations"
        );
        assert!(
            test_ops.iter().any(|op| matches!(op, NonDeterministicOperation::FloatingPoint(_))),
            "Test mode should detect floating point operations"
        );
        
        // Verify both modes detect time dependent operations
        assert!(
            normal_ops.iter().any(|op| matches!(op, NonDeterministicOperation::TimeDependent(_))),
            "Normal mode should detect time dependent operations"
        );
        assert!(
            test_ops.iter().any(|op| matches!(op, NonDeterministicOperation::TimeDependent(_))),
            "Test mode should detect time dependent operations"
        );
        
        // Verify both modes detect the same issues
        assert_eq!(
            normal_ops.len(), 
            test_ops.len(), 
            "Both modes should detect the same number of issues"
        );
        
        Ok(())
    }
    
    #[test]
    fn test_detect_random_number_generation() -> Result<()> {
        // Create a WebAssembly module with random number generation
        let wat = r#"
            (module
                (import "env" "random" (func $random (result i32)))
                (func $get_random (result i32)
                    call $random
                )
                (export "get_random" (func $get_random))
            )
        "#;
        
        let wasm = parse_str(wat)?;
        let module = Module::from_buffer(&wasm)?;
        
        let operations = analyze_determinism(&module);
        
        assert!(!operations.is_empty(), "Should detect random number generation");
        assert!(
            operations.iter().any(|op| 
                matches!(op, NonDeterministicOperation::RandomNumberGeneration(_))
            ),
            "Should include RandomNumberGeneration operation type"
        );
        
        Ok(())
    }
    
    #[test]
    fn test_determinism_circuit_constraints() -> Result<()> {
        // Create operations that would make a module non-deterministic
        let operations = vec![
            NonDeterministicOperation::FloatingPoint(
                "f32.add in function test".to_string()
            )
        ];
        
        // Create a circuit with these operations
        let circuit = DeterminismCircuit::<Fr>::new_with_operations(operations, false);
        
        // Create a constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        // Generate constraints - this should fail because the circuit will create
        // unsatisfiable constraints when operations are present
        circuit.generate_constraints(cs.clone())?;
        
        // Check that the constraints are unsatisfiable
        assert!(!cs.is_satisfied().unwrap(), 
            "Constraint system should be unsatisfiable with non-deterministic operations");
        
        // Create a circuit with no operations
        let circuit = DeterminismCircuit::<Fr>::new_with_operations(vec![], false);
        
        // Create a constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        // Generate constraints - this should succeed
        circuit.generate_constraints(cs.clone())?;
        
        // Check that the constraints are satisfiable
        assert!(cs.is_satisfied().unwrap(), 
            "Constraint system should be satisfiable with no operations");
        
        Ok(())
    }
    
    #[test]
    fn test_test_mode_bypass() -> Result<()> {
        // Create operations that would make a module non-deterministic
        let operations = vec![
            NonDeterministicOperation::FloatingPoint(
                "f32.add in function test".to_string()
            )
        ];
        
        // Create a circuit with these operations but in test mode
        let circuit = DeterminismCircuit::<Fr>::new_with_operations(operations, true);
        
        // Create a constraint system
        let cs = ConstraintSystem::<Fr>::new_ref();
        
        // Generate constraints - this should succeed because we're in test mode
        circuit.generate_constraints(cs.clone())?;
        
        // Check that the constraints are satisfiable even with operations
        assert!(cs.is_satisfied().unwrap(), 
            "Constraint system should be satisfiable in test mode");
        
        Ok(())
    }
}
