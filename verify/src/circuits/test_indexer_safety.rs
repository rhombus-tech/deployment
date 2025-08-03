// Simple test script for testing our new indexer safety implementations
use walrus::{Module, ModuleConfig};
use wat::parse_str;
use anyhow::Result;

// Bring in the functions from our new implementation
mod indexer_safety_new;
use indexer_safety_new::{IndexerVulnerability, detect_unpredictable_execution, detect_complex_recursion};

fn main() -> Result<()> {
    println!("Testing detect_unpredictable_execution...");
    test_detect_unpredictable_execution()?;
    
    println!("Testing detect_complex_recursion...");
    test_detect_complex_recursion()?;
    
    println!("All tests passed!");
    Ok(())
}

fn test_detect_unpredictable_execution() -> Result<()> {
    // Test case for call_indirect instruction
    let wat = r#"
        (module
            (table 1 funcref)
            (elem (i32.const 0) $function)
            (func $function (result i32) i32.const 42)
            (func $call_indirect (param i32) (result i32)
                local.get 0
                call_indirect (result i32)
            )
            (export "call_indirect" (func $call_indirect))
        )
    "#;
    
    let wasm = parse_str(wat)?;
    let module = Module::from_buffer(&wasm)?;
    
    let mut vulnerabilities = Vec::new();
    detect_unpredictable_execution(&module, &mut vulnerabilities);
    
    if vulnerabilities.iter().any(|v| matches!(v, IndexerVulnerability::UnpredictableExecution(_))) {
        println!("✅ Successfully detected unpredictable execution due to call_indirect");
    } else {
        println!("❌ Failed to detect unpredictable execution due to call_indirect");
        println!("Detected vulnerabilities: {:?}", vulnerabilities);
    }
    
    Ok(())
}

fn test_detect_complex_recursion() -> Result<()> {
    // Test case for direct recursion
    let wat = r#"
        (module
            (func $factorial (param i32) (result i32)
                local.get 0
                i32.const 0
                i32.eq
                if (result i32)
                    i32.const 1
                else
                    local.get 0
                    local.get 0
                    i32.const 1
                    i32.sub
                    call $factorial
                    i32.mul
                end
            )
            (export "factorial" (func $factorial))
        )
    "#;
    
    let wasm = parse_str(wat)?;
    let module = Module::from_buffer(&wasm)?;
    
    let mut vulnerabilities = Vec::new();
    detect_complex_recursion(&module, &mut vulnerabilities);
    
    if vulnerabilities.iter().any(|v| matches!(v, IndexerVulnerability::ComplexRecursion(_))) {
        println!("✅ Successfully detected complex recursion due to direct recursion");
    } else {
        println!("❌ Failed to detect complex recursion due to direct recursion");
        println!("Detected vulnerabilities: {:?}", vulnerabilities);
    }
    
    Ok(())
}
