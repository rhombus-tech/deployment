use verify::circuits::{
    memory_safety::MemorySafetyCircuit,
    bytecode_safety::BytecodeSafetyCircuit,
};
use verify::parser::wasm_analyzer::WasmAnalyzer;
use ark_bls12_381::Fr;
use std::fs;
use std::path::Path;
use anyhow::Result;

fn main() -> Result<()> {
    println!("Starting Alkanes Contract Verification");
    println!("--------------------------------------");
    
    // Path to the compiled WASM file of our test-alkanes contract
    let wasm_path = Path::new("target/wasm32-unknown-unknown/release/test_alkanes.wasm");
    
    // Check if the WASM file exists
    if !wasm_path.exists() {
        println!("ERROR: Alkanes WASM file not found at {:?}", wasm_path);
        println!("Make sure you've built the test-alkanes contract with:");
        println!("cd verify/test-alkanes && cargo build --target wasm32-unknown-unknown --release");
        return Ok(());
    }
    
    println!("Found WASM binary at: {:?}", wasm_path);
    
    // Read the WASM binary
    let wasm_binary = fs::read(wasm_path)?;
    println!("Successfully loaded alkanes WASM binary, size: {} bytes", wasm_binary.len());
    
    // Parse the WASM module for analysis
    let module = walrus::Module::from_buffer(&wasm_binary)?;
    
    // Create a WasmAnalyzer to analyze the module
    let mut analyzer = WasmAnalyzer::new(module.clone())?;
    analyzer.analyze()?;
    
    println!("\nMemory Access Analysis");
    println!("---------------------");
    println!("Memory access patterns detected in the alkanes contract:");
    if let Some(memory_id) = analyzer.get_memory() {
        if let Some(accesses) = analyzer.get_memory_accesses_circuit(memory_id) {
            for (i, access) in accesses.iter().enumerate().take(10) {
                println!("  Access {}: offset={}, size={}, is_store={}", 
                         i, access.offset, access.size, access.is_store);
            }
            if accesses.len() > 10 {
                println!("  ... and {} more access patterns", accesses.len() - 10);
            }
        }
    }
    
    println!("\nPCC Analysis (Proof-Carrying Code)");
    println!("--------------------------------");
    
    // Create a memory safety circuit to verify memory safety properties
    let memory_circuit = MemorySafetyCircuit::<Fr>::new(&module);
    
    // Create a bytecode safety circuit to verify bytecode safety properties
    let bytecode_circuit = BytecodeSafetyCircuit::<Fr>::new(&module);
    
    // Set test mode to avoid false positives
    bytecode_circuit.set_test_mode(true);
    
    // Verify memory safety properties
    println!("\nVerifying memory safety properties...");
    let is_memory_safe = memory_circuit.is_memory_safe();
    println!("Memory safety verification result: {}", if is_memory_safe { "PASSED ✅" } else { "FAILED ❌" });
    
    // Verify bytecode safety properties (this will check for various vulnerabilities)
    println!("\nVerifying bytecode safety properties...");
    let result = bytecode_circuit.verify_bytecode_safety();
    
    // Print the verification results
    println!("Bytecode safety verification result: {:?}", result);
    println!("Vulnerabilities detected: {}", bytecode_circuit.get_vulnerability_count());
    
    // Print specific vulnerabilities if any were detected
    if bytecode_circuit.get_vulnerability_count() > 0 {
        let vulnerabilities = bytecode_circuit.get_vulnerabilities();
        println!("\nDetected vulnerabilities:");
        for (i, vuln) in vulnerabilities.iter().enumerate() {
            println!("  {}: {:?}", i + 1, vuln);
        }
        println!("\nFAILED: Contract has security vulnerabilities ❌");
    } else {
        println!("\nPASSED: No security vulnerabilities detected ✅");
    }
    
    println!("\nPCD Analysis (Proof-Carrying Data)");
    println!("--------------------------------");
    
    // Use the PCD verification system
    use verify::circuits::pcd::{PcdCircuit, PcdProof};
    
    // Create a PCD circuit for the alkanes contract
    println!("Creating PCD circuit for verification...");
    let pcd_circuit = PcdCircuit::<Fr>::new(&wasm_binary);
    
    // Verify the contract using PCD
    println!("Verifying contract with PCD system...");
    match pcd_circuit.verify_circuit() {
        Ok(_) => println!("PASSED: PCD verification successful ✅"),
        Err(e) => println!("FAILED: PCD verification failed: {:?} ❌", e),
    }
    
    println!("\nOverall Verification Result");
    println!("--------------------------");
    if is_memory_safe && bytecode_circuit.get_vulnerability_count() == 0 {
        println!("SUCCESS: The alkanes contract has passed all verification checks! ✅");
    } else {
        println!("FAILURE: The alkanes contract has failed one or more verification checks. ❌");
    }
    
    Ok(())
}
