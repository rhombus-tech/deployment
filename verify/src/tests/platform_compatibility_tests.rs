use crate::circuits::{
    indexer_safety::IndexerSafetyCircuit,
    side_channel::SideChannelSafetyCircuit,
};
use crate::parser::wasm_analyzer::WasmAnalyzer;
use anyhow::Result;
use ark_bls12_381::Fr;
use walrus::Module;

/// Test for platform-specific configurations
#[test]
fn test_alkanes_platform_settings() -> Result<()> {
    // Create a test module
    let module = create_test_module()?;
    
    // Create an indexer safety circuit for Alkanes with 5M fuel limit
    let mut circuit = IndexerSafetyCircuit::<Fr>::new(&module);
    
    // Set Alkanes-specific parameters for 5M fuel
    circuit.set_max_loop_iterations(50000)  // 50x higher than default
           .set_max_memory_pages(500);      // 5x higher than default
    
    // Ensure circuit is properly configured
    assert_eq!(circuit.get_max_loop_iterations(), 50000);
    assert_eq!(circuit.get_max_memory_pages(), 500);
    
    // Set test mode to avoid false positives
    circuit.set_test_mode(true);
    
    Ok(())
}

/// Test for Wasmlanche-specific side channel detection
#[test]
fn test_wasmlanche_side_channel_detection() -> Result<()> {
    // Create a test module with side channel vulnerability
    let module = create_module_with_side_channel()?;
    
    // Create a side channel safety circuit (used by Wasmlanche platform)
    let circuit = SideChannelSafetyCircuit::<Fr>::new(&module);
    
    // Should detect side channel vulnerabilities
    assert!(!circuit.vulnerabilities.is_empty());
    
    Ok(())
}

// Helper function to create a test module
fn create_test_module() -> Result<Module> {
    let wat = r#"
        (module
          (func $add (param $a i32) (param $b i32) (result i32)
            (i32.add (local.get $a) (local.get $b))
          )
          (export "add" (func $add))
        )
    "#;
    
    // Parse the WAT format to a module
    let binary = wat::parse_str(wat)?;
    let module = Module::from_buffer(&binary)?;
    
    Ok(module)
}

// Helper function to create a module with side channel vulnerability
fn create_module_with_side_channel() -> Result<Module> {
    let wat = r#"
        (module
          (func $vulnerable_compare (param $secret i32) (param $guess i32) (result i32)
            (local $i i32)
            (local $result i32)
            
            ;; Initialize result
            (local.set $result (i32.const 1))
            
            ;; Time-dependent comparison (classic side channel)
            (loop $check
              (br_if $check
                (i32.and
                  (i32.lt_s (local.get $i) (i32.const 32))
                  (i32.eq
                    (i32.and 
                      (i32.shr_u (local.get $secret) (local.get $i))
                      (i32.const 1)
                    )
                    (i32.and
                      (i32.shr_u (local.get $guess) (local.get $i))
                      (i32.const 1)
                    )
                  )
                )
              )
              
              ;; Increment index
              (local.set $i (i32.add (local.get $i) (i32.const 1)))
            )
            
            ;; Return result
            (local.get $result)
          )
          (export "compare" (func $vulnerable_compare))
        )
    "#;
    
    // Parse the WAT format to a module
    let binary = wat::parse_str(wat)?;
    let module = Module::from_buffer(&binary)?;
    
    Ok(module)
}
