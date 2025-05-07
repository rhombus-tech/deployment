//! Tests for indexer safety circuit
//! 
//! These tests verify that our indexer safety circuit correctly identifies
//! unsafe patterns in WebAssembly modules, focusing on:
//! 
//! 1. Unpredictable execution (call_indirect instructions)
//! 2. Data-dependent control flow
//! 3. Missing bounds checks
//! 4. Floating point operations in loops
//! 5. Various forms of recursion (direct, mutual, non-tail)

// No need for wast::parser::Parse
use walrus::Module;
use anyhow::Result;
use wat::parse_str;

use crate::circuits::indexer_safety::{IndexerSafetyCircuit, IndexerVulnerability};
// No need for WasmAnalyzer in these tests
use ark_bls12_381::Fr;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};

/// Test that the circuit correctly detects unpredictable execution (call_indirect instructions)
#[test]
fn test_detect_unpredictable_execution() -> Result<()> {
    // Test case for call_indirect instruction
    let wat = r#"
        (module
            (type $type0 (func (param i32) (result i32)))
            (table 1 funcref)
            (elem (i32.const 0) $func)
            
            (func $func (param i32) (result i32)
                local.get 0
                i32.const 1
                i32.add
            )
            
            (func (export "run") (param i32) (result i32)
                (local $idx i32)
                ;; Use input as table index
                local.get 0
                local.set $idx
                
                ;; Call indirect - unpredictable execution
                local.get 0
                local.get $idx
                call_indirect (type $type0)
            )
        )
    "#;

    let wasm = parse_str(wat)?;
    let module = Module::from_buffer(&wasm)?;
    
    // Print module info for debugging
    println!("Module functions: {}", module.funcs.iter().count());
    for function in module.funcs.iter() {
        println!("Function name: {:?}", function.name);
        if let walrus::FunctionKind::Local(local_func) = &function.kind {
            let block = local_func.block(local_func.entry_block());
            println!("Instructions: {}", block.instrs.len());
            for (instr, _) in &block.instrs {
                println!("Instruction: {:?}", instr);
            }
        }
    }
    
    let mut vulnerabilities = Vec::new();
    crate::circuits::indexer_safety::detect_unpredictable_execution(&module, &mut vulnerabilities);
    println!("Found {} vulnerabilities", vulnerabilities.len());
    assert!(!vulnerabilities.is_empty(), "Should detect unpredictable execution");
    println!("Detected vulnerabilities: {:?}", vulnerabilities);
    
    Ok(())
}

/// Test that the circuit correctly detects data-dependent control flow
#[test]
fn test_detect_data_dependent_control_flow() -> Result<()> {
    // Test case for data-dependent control flow
    let wat = r#"
        (module
            (func (export "run") (param i32) (result i32)
                ;; Use input for conditional branch - data-dependent control flow
                local.get 0
                (if (result i32)
                    (then
                        i32.const 42
                    )
                    (else
                        i32.const 24
                    )
                )
            )
        )
    "#;

    let wasm = parse_str(wat)?;
    let module = Module::from_buffer(&wasm)?;
    
    // Print module info for debugging
    println!("Module functions: {}", module.funcs.iter().count());
    for function in module.funcs.iter() {
        println!("Function name: {:?}", function.name);
        if let walrus::FunctionKind::Local(local_func) = &function.kind {
            let block = local_func.block(local_func.entry_block());
            println!("Instructions: {}", block.instrs.len());
            for (instr, _) in &block.instrs {
                println!("Instruction: {:?}", instr);
            }
        }
    }
    
    // Examine local variables in the module for debugging
    for function in module.funcs.iter() {
        if let walrus::FunctionKind::Local(local_func) = &function.kind {
            println!("Function locals: {}", local_func.args.len());
            for (i, local) in local_func.args.iter().enumerate() {
                println!("Arg {}: {:?}", i, local);
            }
            
            let entry_block = local_func.block(local_func.entry_block());
            println!("Prior instruction: none"); // No prior instruction before the first one
            let mut prior_instr = None;
            
            for (i, (instr, _)) in entry_block.instrs.iter().enumerate() {
                println!("Instruction {}: {:?}", i, instr);
                println!("  - Previous was: {:?}", prior_instr);
                prior_instr = Some(instr);
            }
        }
    }
    
    let mut vulnerabilities = Vec::new();
    // Call the detection function with a custom closure for debugging
    crate::circuits::indexer_safety::detect_data_dependent_control_flow(&module, &mut vulnerabilities);
    println!("Found {} vulnerabilities", vulnerabilities.len());
    assert!(!vulnerabilities.is_empty(), "Should detect data-dependent control flow");
    println!("Detected vulnerabilities: {:?}", vulnerabilities);
    
    Ok(())
}

/// Test that the circuit correctly detects missing bounds checks
#[test]
fn test_detect_missing_bounds_check() -> Result<()> {
    // Test case for memory access without bounds check
    let wat = r#"
        (module
            (memory 1)
            (func (export "run") (param i32) (result i32)
                local.get 0  ;; Use input as memory index without bounds check
                i32.load
                return
            )
        )
    "#;

    let wasm = parse_str(wat)?;
    let module = Module::from_buffer(&wasm)?;
    
    let mut vulnerabilities = Vec::new();
    crate::circuits::indexer_safety::detect_missing_bounds_check(&module, &mut vulnerabilities);
    assert!(!vulnerabilities.is_empty(), "Should detect missing bounds check");
    println!("Detected vulnerabilities: {:?}", vulnerabilities);
    
    Ok(())
}

/// Test that the circuit correctly detects floating point operations in loops
#[test]
fn test_detect_floating_point_in_loop() -> Result<()> {
    // Test case for floating point operations in a loop
    let wat = r#"
        (module
            (func (export "run") (param f32) (result f32)
                (local $i i32)
                (local $result f32)
                ;; Initialize variables
                local.get 0
                local.set $result
                i32.const 0
                local.set $i
                
                ;; Loop structure with floating point operation
                (loop $my_loop
                    ;; Floating point operation inside a loop
                    local.get $result
                    f32.const 1.5
                    f32.add
                    local.set $result
                    
                    ;; Increment counter
                    local.get $i
                    i32.const 1
                    i32.add
                    local.set $i
                    
                    ;; Loop condition
                    local.get $i
                    i32.const 10
                    i32.lt_s
                    (br_if $my_loop)
                )
                
                ;; Return result
                local.get $result
            )
        )
    "#;

    let wasm = parse_str(wat)?;
    let module = Module::from_buffer(&wasm)?;
    
    // Print module info for debugging
    println!("Module functions: {}", module.funcs.iter().count());
    for function in module.funcs.iter() {
        println!("Function name: {:?}", function.name);
        if let walrus::FunctionKind::Local(local_func) = &function.kind {
            let block = local_func.block(local_func.entry_block());
            println!("Instructions: {}", block.instrs.len());
            for (instr, _) in &block.instrs {
                println!("Instruction: {:?}", instr);
            }
        }
    }
    
    let mut vulnerabilities = Vec::new();
    crate::circuits::indexer_safety::detect_floating_point_in_loop(&module, &mut vulnerabilities);
    println!("Found {} vulnerabilities", vulnerabilities.len());
    assert!(!vulnerabilities.is_empty(), "Should detect floating point in loop");
    println!("Detected vulnerabilities: {:?}", vulnerabilities);
    
    Ok(())
}

/// Test that the circuit correctly detects direct recursion
#[test]
fn test_detect_direct_recursion() -> Result<()> {
    // Test case for direct recursion
    let wat = r#"
        (module
            (func $recursive (export "recursive") (param i32) (result i32)
                ;; Classic recursive factorial function with direct recursion
                local.get 0
                i32.const 0
                i32.eq
                (if (result i32)
                    (then
                        i32.const 1
                    )
                    (else
                        local.get 0
                        i32.const 1
                        i32.sub
                        call $recursive  ;; Direct recursion
                        local.get 0
                        i32.mul
                    )
                )
            )
        )
    "#;

    let wasm = parse_str(wat)?;
    let module = Module::from_buffer(&wasm)?;
    
    // Print module info for debugging
    println!("Module functions: {}", module.funcs.iter().count());
    for function in module.funcs.iter() {
        println!("Function name: {:?}", function.name);
        if let walrus::FunctionKind::Local(local_func) = &function.kind {
            let block = local_func.block(local_func.entry_block());
            println!("Instructions: {}", block.instrs.len());
            for (instr, _) in &block.instrs {
                println!("Instruction: {:?}", instr);
            }
        }
    }
    
    let mut vulnerabilities = Vec::new();
    crate::circuits::indexer_safety::detect_complex_recursion(&module, &mut vulnerabilities);
    println!("Found {} vulnerabilities", vulnerabilities.len());
    assert!(!vulnerabilities.is_empty(), "Should detect direct recursion");
    println!("Detected vulnerabilities: {:?}", vulnerabilities);
    
    Ok(())
}

/// Test the complete indexer safety circuit
#[test]
fn test_indexer_safety_circuit_constraints() -> Result<()> {
    let vulnerabilities = vec![
        IndexerVulnerability::UnpredictableExecution("Test unpredictable execution".to_string()),
        IndexerVulnerability::ComplexRecursion("Test complex recursion".to_string()),
        IndexerVulnerability::UnpredictableExecution("Test data dependent control flow".to_string()),
    ];
    
    // Create a constraint system
    let cs = ConstraintSystem::<Fr>::new_ref();
    
    // Create a circuit with the vulnerabilities
    let circuit = IndexerSafetyCircuit::<Fr>::new_with_vulnerabilities(vulnerabilities, false);
    
    // Generate constraints
    let result = circuit.generate_constraints(cs.clone());
    assert!(result.is_ok(), "Should generate constraints without error");
    
    // The constraint system should be unsatisfiable if vulnerabilities are present
    assert!(!cs.is_satisfied().unwrap(), "Constraint system should be unsatisfiable with vulnerabilities");
    
    println!("Constraint system: {:?}", cs);
    println!("Number of constraints: {}", cs.num_constraints());
    
    Ok(())
}
