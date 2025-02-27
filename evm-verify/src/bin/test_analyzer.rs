use anyhow::Result;
use evm_verify::bytecode::analyzer::BytecodeAnalyzer;
use hex_literal::hex;

fn main() -> Result<()> {
    println!("Testing EVM Bytecode Analyzer");
    println!("=============================\n");

    // Test bytecode with various opcodes
    // This bytecode includes a mix of arithmetic, storage, control flow, and other operations
    let test_bytecode = hex!("
        60806040526004361061001e5760003560e01c80635c60da1b14610023575b600080fd5b61004e6004803603602081101561003957600080fd5b81019080803590602001909291905050506100a9565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101561008e578082015181840152602081019050610073565b50505050905090810190601f1680156100bb5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b60606000826040518082805190602001908083835b602083106100e257805182526020820191506020810190506020830392506100bf565b6001836020036101000a03801982511681845116808217855250505050505090500191505060405180910390206040518060400160405280600a81526020017f68656c6c6f20776f726c64000000000000000000000000000000000000000000815250915050919050565b
    ");

    // Create a bytecode analyzer
    let mut analyzer = BytecodeAnalyzer::new((&test_bytecode).into());
    // Set test mode to false since we want to see the memory accesses in this case
    analyzer.set_test_mode(false);

    // Analyze the bytecode
    match analyzer.analyze() {
        Ok(analysis_result) => {
            println!("✅ Bytecode analysis completed successfully!");
            println!("\nAnalysis Results:");
            println!("-----------------");
            
            // Print runtime information
            println!("\nRuntime Information:");
            println!("  Code Length: {} bytes", analysis_result.runtime.code_length);
            
            // Print memory accesses
            println!("\nMemory Accesses:");
            for access in &analysis_result.memory_accesses {
                println!("  - Offset 0x{:x}: {} (PC: {})", 
                    access.offset, 
                    if access.write { "Write" } else { "Read" },
                    access.pc);
            }
            
            // Print warnings
            println!("\nWarnings:");
            for warning in &analysis_result.warnings {
                println!("  - {}", warning);
            }
            
            // Print delegate calls
            println!("\nDelegate Calls:");
            for call in &analysis_result.delegate_calls {
                println!("  - Target: {:?}, PC: {}, Depth: {}", 
                    call.target, call.pc, call.depth);
            }
        },
        Err(e) => {
            println!("❌ Bytecode analysis failed: {}", e);
        }
    }

    // Test specific opcodes
    test_specific_opcodes()?;

    println!("\nAll tests completed!");
    Ok(())
}

fn test_specific_opcodes() -> Result<()> {
    println!("\nTesting Specific Opcodes");
    println!("=======================\n");

    // Test arithmetic opcodes
    let arithmetic_bytecode = hex!("
        6001600201600301600401600501600601600701600801600901600a0b
    ");
    
    println!("Testing Arithmetic Opcodes...");
    let mut analyzer = BytecodeAnalyzer::new((&arithmetic_bytecode).into());
    analyzer.set_test_mode(true);
    match analyzer.analyze() {
        Ok(_) => println!("✅ Arithmetic opcodes test passed!"),
        Err(e) => println!("❌ Arithmetic opcodes test failed: {}", e),
    }

    // Test environmental opcodes
    let env_bytecode = hex!("
        3031323334353637383940414243444546474849
    ");
    
    println!("\nTesting Environmental Opcodes...");
    let mut analyzer = BytecodeAnalyzer::new((&env_bytecode).into());
    analyzer.set_test_mode(true);
    match analyzer.analyze() {
        Ok(_) => println!("✅ Environmental opcodes test passed!"),
        Err(e) => println!("❌ Environmental opcodes test failed: {}", e),
    }

    // Test storage opcodes
    let storage_bytecode = hex!("
        6001600255600154
    ");
    
    println!("\nTesting Storage Opcodes...");
    let mut analyzer = BytecodeAnalyzer::new((&storage_bytecode).into());
    analyzer.set_test_mode(true);
    match analyzer.analyze() {
        Ok(_) => println!("✅ Storage opcodes test passed!"),
        Err(e) => println!("❌ Storage opcodes test failed: {}", e),
    }

    // Test contract interaction opcodes
    let contract_bytecode = hex!("
        60006000600060006000731234567890123456789012345678901234567890620186a0f1
        60006000600060006000731234567890123456789012345678901234567890620186a0f2
        60006000600060006000731234567890123456789012345678901234567890620186a0f4
        60006000600060006000731234567890123456789012345678901234567890620186a0fa
    ");
    
    println!("\nTesting Contract Interaction Opcodes...");
    let mut analyzer = BytecodeAnalyzer::new((&contract_bytecode).into());
    analyzer.set_test_mode(true);
    match analyzer.analyze() {
        Ok(_) => println!("✅ Contract interaction opcodes test passed!"),
        Err(e) => println!("❌ Contract interaction opcodes test failed: {}", e),
    }

    // Test terminal opcodes
    let terminal_bytecode = hex!("
        6000600060016000f3
        6000600060026000fd
        6000ff00
    ");
    
    println!("\nTesting Terminal Opcodes...");
    let mut analyzer = BytecodeAnalyzer::new((&terminal_bytecode).into());
    analyzer.set_test_mode(true);
    match analyzer.analyze() {
        Ok(_) => println!("✅ Terminal opcodes test passed!"),
        Err(e) => println!("❌ Terminal opcodes test failed: {}", e),
    }

    Ok(())
}
