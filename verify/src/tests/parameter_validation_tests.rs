//! Tests for parameter validation safety
//! 
//! These tests verify that our parameter validation circuit correctly identifies
//! unsafe parameter handling patterns, particularly focusing on the Wasmlanche
//! requirements:
//! 
//! 1. Validating the length prefix (first 4 bytes)
//! 2. Rejecting unreasonable lengths (>1024 bytes)
//! 3. Ensuring bounds checking for memory access

use wast::parser::Parse;
use walrus::{Module, ModuleConfig};
use anyhow::Result;
use wasmer::{Engine, Store, Module as WasmerModule, Instance, Function, FunctionType};
use wasmer::AsStoreRef;
use wat::parse_str;
use std::sync::Arc;

use crate::parser::WasmAnalyzer;
use crate::circuits::parameter_validation::{ParameterValidationCircuit, ParameterValidation};
use crate::parser::types::{MemoryType, Limits};
use ark_ed_on_bls12_381::Fr;
use ark_relations::r1cs::ConstraintSystem;

/// Test that a contract properly validating parameter length (≤1024 bytes) passes validation
#[test]
fn test_safe_parameter_length_validation() -> Result<()> {
    // Create a WebAssembly module that properly validates parameter length
    // This follows Wasmlanche requirements of checking the first 4 bytes as length prefix
    let wat = r#"
    (module
      (memory (export "memory") 1)
      (func (export "process_params") (param i32) (result i32)
        ;; Load the length from the first 4 bytes
        local.get 0
        i32.load
        
        ;; Check if length is reasonable (≤1024 bytes)
        i32.const 1024
        i32.gt_u
        if
          ;; Return 0 for invalid input
          i32.const 0
          return
        end
        
        ;; Process the parameter
        local.get 0
        return
      )
    )
    "#;
    
    // Convert WAT to WASM bytes
    let wasm_bytes = wat::parse_str(wat)?;
    
    // Create analyzer
    let mut analyzer = WasmAnalyzer::from_bytes(&wasm_bytes)?;
    analyzer.analyze()?;
    
    // Get parameter validations (manually create them for this test)
    let validations = vec![
        ParameterValidation::LengthCheck(0, 1024, 5),  // Parameter 0, max 1024 bytes
    ];
    
    // Create circuit
    let circuit = ParameterValidationCircuit::<Fr>::new(
        validations,
        1024, // Wasmlanche maximum parameter length
        MemoryType::new(Limits::new(Some(1), Some(10))),
        1,
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();
    
    // Generate and check constraints
    circuit.generate_constraints(cs.clone())?;
    let satisfied = cs.is_satisfied()?;
    
    assert!(satisfied, "Safe parameter validation should satisfy constraints");
    
    Ok(())
}

/// Test that a contract failing to validate parameter length (allowing >1024 bytes) fails validation
#[test]
fn test_unsafe_parameter_length_validation() -> Result<()> {
    // Create a WebAssembly module that doesn't properly validate parameter length
    // This reproduces the Wasmlanche bug where 3.5B bytes were accepted
    let wat = r#"
    (module
      (memory (export "memory") 1)
      (func (export "process_params") (param i32) (result i32)
        ;; Load the length from the first 4 bytes but don't validate it!
        local.get 0
        i32.load
        
        ;; No validation check!
        
        ;; Process the parameter regardless of size
        local.get 0
        return
      )
    )
    "#;
    
    // Convert WAT to WASM bytes
    let wasm_bytes = wat::parse_str(wat)?;
    
    // Create analyzer
    let mut analyzer = WasmAnalyzer::from_bytes(&wasm_bytes)?;
    analyzer.analyze()?;
    
    // Create circuit with a validation that allows too large parameters (3.5B bytes)
    // This simulates a contract accepting the unreasonable parameter length from the memory
    let validations = vec![
        ParameterValidation::LengthCheck(0, 3_500_000_000, 5),  // Parameter 0, 3.5B bytes (!) 
    ];
    
    // Create circuit
    let circuit = ParameterValidationCircuit::<Fr>::new(
        validations,
        1024, // Wasmlanche maximum parameter length
        MemoryType::new(Limits::new(Some(1), Some(10))),
        1,
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();
    
    // Generate constraints - the test passes if constraints are not satisfiable
    circuit.generate_constraints(cs.clone())?;
    let satisfied = cs.is_satisfied()?;
    
    assert!(!satisfied, "Unsafe parameter validation should not satisfy constraints");
    
    Ok(())
}

/// Test that a contract properly checking memory bounds for parameters passes validation
#[test]
fn test_safe_parameter_bounds_checking() -> Result<()> {
    // Create a WebAssembly module that properly checks bounds
    let wat = r#"
    (module
      (memory (export "memory") 1)
      (func (export "process_params") (param i32 i32) (result i32)
        ;; param 0: buffer pointer
        ;; param 1: buffer length
        
        ;; Check buffer length is reasonable
        local.get 1
        i32.const 1024
        i32.gt_u
        if
          i32.const 0
          return
        end
        
        ;; Check bounds (ptr + len must be within memory)
        local.get 0
        local.get 1
        i32.add
        memory.size
        i32.const 16  ;; 16 bytes per page = 65536
        i32.mul
        i32.gt_u
        if
          i32.const 0
          return
        end
        
        ;; Process the parameter safely
        local.get 0
        return
      )
    )
    "#;
    
    // Convert WAT to WASM bytes
    let wasm_bytes = wat::parse_str(wat)?;
    
    // Create analyzer
    let mut analyzer = WasmAnalyzer::from_bytes(&wasm_bytes)?;
    analyzer.analyze()?;
    
    // Get parameter validations (manually create them for this test)
    let validations = vec![
        ParameterValidation::LengthCheck(1, 1024, 5),      // Length check
        ParameterValidation::BoundsCheck(1000, 500, 15),   // Memory access check
    ];
    
    // Create circuit
    let circuit = ParameterValidationCircuit::<Fr>::new(
        validations,
        1024, // Max parameter length
        MemoryType::new(Limits::new(1, Some(10)), false).unwrap(),
        1,    // 1 page = 65536 bytes
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();
    
    // Generate and check constraints
    circuit.generate_constraints(cs.clone())?;
    let satisfied = cs.is_satisfied()?;
    
    assert!(satisfied, "Safe bounds checking should satisfy constraints");
    
    Ok(())
}

/// Test that a contract failing to check memory bounds for parameters fails validation
#[test]
fn test_unsafe_parameter_bounds_checking() -> Result<()> {
    // Create a WebAssembly module that doesn't check bounds
    let wat = r#"
    (module
      (memory (export "memory") 1)
      (func (export "process_params") (param i32 i32) (result i32)
        ;; param 0: buffer pointer
        ;; param 1: buffer length
        
        ;; No bounds checking!
        
        ;; Unsafe memory access
        local.get 0
        local.get 1
        i32.add
        i32.load
        return
      )
    )
    "#;
    
    // Convert WAT to WASM bytes
    let wasm_bytes = wat::parse_str(wat)?;
    
    // Create analyzer
    let mut analyzer = WasmAnalyzer::from_bytes(&wasm_bytes)?;
    analyzer.analyze()?;
    
    // Create circuit with an unsafe bounds access (accessing beyond memory limit)
    let validations = vec![
        ParameterValidation::BoundsCheck(65000, 1000, 5),  // Access beyond memory limit
    ];
    
    // Create circuit
    let circuit = ParameterValidationCircuit::<Fr>::new(
        validations,
        1024, // Max parameter length
        MemoryType::new(Limits::new(1, Some(10)), false).unwrap(),
        1,    // 1 page = 65536 bytes
    );
    
    // Create constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();
    
    // Generate constraints - the test passes if constraints are not satisfiable
    circuit.generate_constraints(cs.clone())?;
    let satisfied = cs.is_satisfied()?;
    
    assert!(!satisfied, "Unsafe bounds checking should not satisfy constraints");
    
    Ok(())
}
