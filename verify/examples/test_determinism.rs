use anyhow::Result;
use verify::circuits::determinism::{analyze_determinism, analyze_determinism_with_options, NonDeterministicOperation, DeterminismCircuit};
use walrus::Module;
use wat::parse_str;
use ark_ff::One;
use ark_relations::r1cs::ConstraintSystem;
use ark_bls12_381::Fr;

// Type alias for BLS12-381 scalar field
type F = Fr;

fn main() -> Result<()> {
    println!("=== Testing Determinism Analyzer ===\n");
    
    // Create a WebAssembly module with floating point operations
    let wat = r#"
        (module
            (func $float_ops (param f32 f32) (result f32)
                local.get 0
                local.get 1
                f32.add
            )
            (import "env" "clock" (func $get_time (result i64)))
            (export "float_ops" (func $float_ops))
        )
    "#;
    
    let wasm = parse_str(wat)?;
    let module = Module::from_buffer(&wasm)?;
    
    // Test 1: Standard mode (should detect non-deterministic operations)
    println!("Test 1: Standard Analysis Mode");
    let operations = analyze_determinism(&module);
    
    if operations.is_empty() {
        println!("❌ No non-deterministic operations detected (expected some)\n");
    } else {
        println!("✅ Detected non-deterministic operations:");
        for (i, op) in operations.iter().enumerate() {
            println!("  {}. {}", i+1, op);
        }
        println!();
    }
    
    // Test 2: Test mode (should still detect but bypass validation)
    println!("Test 2: Test Mode Analysis");
    let test_operations = analyze_determinism_with_options(&module, true);
    
    if test_operations.is_empty() {
        println!("✅ No operations detected in test mode (as expected)\n");
    } else {
        println!("❌ Detected operations in test mode (limited checks):");
        for (i, op) in test_operations.iter().enumerate() {
            println!("  {}. {}", i+1, op);
        }
        println!();
    }
    
    // Test 3: Circuit in normal mode (should fail constraints)
    println!("Test 3: Circuit Validation in Normal Mode");
    test_circuit_validation(&module, false)?;
    
    // Test 4: Circuit in test mode (should succeed despite non-determinism)
    println!("\nTest 4: Circuit Validation in Test Mode");
    test_circuit_validation(&module, true)?;
    
    Ok(())
}

/// Test the determinism circuit with the given module and test mode setting
fn test_circuit_validation(module: &Module, test_mode: bool) -> Result<()> {
    // Create a constraint system
    let cs = ConstraintSystem::<F>::new_ref();
    
    // Create a determinism circuit with the test mode setting
    let mut circuit = DeterminismCircuit::<F>::new(module.clone());
    circuit.set_test_mode(test_mode);
    
    // Generate constraints
    match circuit.generate_constraints(cs.clone()) {
        Ok(_) => {
            // Check if constraints are satisfied
            let is_satisfied = cs.is_satisfied().unwrap_or(false);
            if is_satisfied {
                println!("✅ Circuit constraints satisfied{}", 
                    if test_mode { " (test mode enabled)" } else { "" });
            } else {
                println!("❌ Circuit constraints not satisfied{}", 
                    if test_mode { " (despite test mode)" } else { " (expected in normal mode)" });
            }
        },
        Err(e) => {
            println!("❌ Error generating constraints: {}", e);
        }
    }
    
    Ok(())
}
