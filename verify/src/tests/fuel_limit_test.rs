//! Tests for the 5M fuel limit implementation for Alkanes platform
//! 
//! This test verifies that our indexer safety circuit correctly applies the 
//! 5M fuel limit parameters, which include:
//! 1. Increased loop iteration limit from 1,000 to 50,000
//! 2. Increased memory page limit from 100 to 500 (~32MB)

use walrus::Module;
use anyhow::Result;
use wat::parse_str;

use crate::circuits::indexer_safety::{IndexerSafetyCircuit, IndexerVulnerability};
use ark_bls12_381::Fr;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};

/// Test that the circuit correctly applies the 5M fuel settings
#[test]
fn test_alkanes_5m_fuel_limits() -> Result<()> {
    // A module with a large loop but under the new 5M fuel limits
    let wat = r#"
        (module
            (func $large_loop_but_within_limit (export "large_loop")
                (local $i i32)
                ;; Initialize counter
                i32.const 0
                local.set $i
                
                ;; Loop up to 40,000 iterations (below 50,000 limit)
                (loop
                    ;; Increment counter
                    local.get $i
                    i32.const 1
                    i32.add
                    local.set $i
                    
                    ;; Check if we've reached 40,000
                    local.get $i
                    i32.const 40000
                    i32.lt_s
                    br_if 0
                )
            )
        )
    "#;
    
    // Parse the WebAssembly module
    let module = parse_str(wat)?;
    
    // Create the circuit without test mode to ensure real validation
    let mut circuit = IndexerSafetyCircuit::<Fr>::new(&module);
    circuit.set_test_mode(false);
    
    // Verify that our 5M fuel limits are correctly set
    assert_eq!(circuit.max_loop_iterations, 50000, "Loop iteration limit should be 50,000");
    assert_eq!(circuit.max_memory_pages, 500, "Memory page limit should be 500");
    
    // No vulnerabilities should be detected as the loop is within our new limits
    assert!(circuit.vulnerabilities.is_empty(), 
        "No vulnerabilities should be detected for loops below the new 50,000 limit");
    
    // Verify circuit constraints
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone())?;
    assert!(cs.is_satisfied()?, "Constraints should be satisfied");
    
    // Now test a module that exceeds the new limits
    let excessive_wat = r#"
        (module
            (func $loop_exceeding_5m_limit (export "excessive_loop")
                (local $i i32)
                ;; Initialize counter
                i32.const 0
                local.set $i
                
                ;; Loop with 60,000 iterations (above 50,000 limit)
                (loop
                    ;; Increment counter
                    local.get $i
                    i32.const 1
                    i32.add
                    local.set $i
                    
                    ;; Check if we've reached 60,000
                    local.get $i
                    i32.const 60000
                    i32.lt_s
                    br_if 0
                )
            )
        )
    "#;
    
    // Parse the excessive WebAssembly module
    let excessive_module = parse_str(excessive_wat)?;
    
    // Create the circuit
    let excessive_circuit = IndexerSafetyCircuit::<Fr>::new(&excessive_module);
    
    // Verify that a vulnerability is detected for exceeding the loop limit
    assert!(!excessive_circuit.vulnerabilities.is_empty(), 
        "A vulnerability should be detected for loops exceeding the new 50,000 limit");
    
    // Check if the specific vulnerability is related to unbounded loops
    let has_unbounded_loop = excessive_circuit.vulnerabilities.iter().any(|v| {
        matches!(v, IndexerVulnerability::UnboundedLoop(_))
    });
    assert!(has_unbounded_loop, "Should detect unbounded loop vulnerability");
    
    Ok(())
}

/// Test the memory page limits for the 5M fuel configuration
#[test]
fn test_memory_page_limits() -> Result<()> {
    // A module with memory usage within the new 5M fuel limits
    let wat = r#"
        (module
            (memory 450)  ;; 450 pages is below the 500 page limit
            
            (func $use_memory (export "use_memory") (param i32) (result i32)
                ;; Use some memory
                local.get 0
                i32.const 42
                i32.store
                
                local.get 0
                i32.load
            )
        )
    "#;
    
    // Parse the WebAssembly module
    let module = parse_str(wat)?;
    
    // Create the circuit
    let circuit = IndexerSafetyCircuit::<Fr>::new(&module);
    
    // No vulnerabilities should be detected as the memory usage is within our new limits
    assert!(circuit.vulnerabilities.is_empty(), 
        "No vulnerabilities should be detected for memory usage below the new 500 page limit");
    
    // Now test a module that exceeds the new memory limits
    let excessive_wat = r#"
        (module
            (memory 550)  ;; 550 pages exceeds the 500 page limit
            
            (func $use_excessive_memory (export "use_memory") (param i32) (result i32)
                ;; Use some memory
                local.get 0
                i32.const 42
                i32.store
                
                local.get 0
                i32.load
            )
        )
    "#;
    
    // Parse the excessive WebAssembly module
    let excessive_module = parse_str(excessive_wat)?;
    
    // Create the circuit
    let excessive_circuit = IndexerSafetyCircuit::<Fr>::new(&excessive_module);
    
    // Verify that a vulnerability is detected for exceeding the memory limit
    assert!(!excessive_circuit.vulnerabilities.is_empty(), 
        "A vulnerability should be detected for memory usage exceeding the new 500 page limit");
    
    // Check if the specific vulnerability is related to excessive memory usage
    let has_excessive_memory = excessive_circuit.vulnerabilities.iter().any(|v| {
        matches!(v, IndexerVulnerability::ExcessiveMemoryUsage(_))
    });
    assert!(has_excessive_memory, "Should detect excessive memory usage vulnerability");
    
    Ok(())
}
