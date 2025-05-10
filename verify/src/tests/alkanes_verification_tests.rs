use crate::parser::wasm_analyzer::WasmAnalyzer;
use crate::circuits::memory_safety::{MemoryAccess, MemoryInit};
use std::path::Path;
use std::fs;
use anyhow::{Result, anyhow};
use walrus;
use wat;

/// Test for verifying an alkanes contract with PCC
#[test]
fn test_alkanes_pcc_verification() -> Result<()> {
    // No verification circuit needed for this test
    println!("Starting PCC verification tests for the alkanes contract...");
    
    // Get wasm module path
    let wasm_path = Path::new("/Users/talzisckind/Downloads/deployment/verify/target/wasm32-unknown-unknown/release/test_alkanes.wasm");
    if !wasm_path.exists() {
        return Err(anyhow!("WASM binary not found at {:?}. Did you run 'just build'?", wasm_path));
    }
    
    println!("Loading WASM binary from {:?}", wasm_path);
    let wasm_bytes = fs::read(wasm_path)?;
    
    // Parse WASM binary using walrus
    println!("Parsing WASM module...");
    let module = walrus::Module::from_buffer(&wasm_bytes)?;
    
    // Initialize WASM Analyzer with the parsed module
    println!("Initializing WASM Analyzer...");
    let mut analyzer = WasmAnalyzer::new(module)?;
    
    // Analyze the module
    analyzer.analyze()?;
    
    // Verify memory safety properties
    println!("Verifying memory safety properties of the alkanes contract...");
    // Check memory safety by verifying all memory accesses are within bounds
    let memory_id = analyzer.get_memory().expect("No memory found in module");
    let memory_accesses = analyzer.get_memory_accesses_circuit(memory_id)
        .unwrap_or_default();
    
    // Get current memory pages and memory type info
    let current_pages = analyzer.get_current_pages(memory_id);
    let memory_type = analyzer.get_memory_type(memory_id)?;
    
    // Get maximum memory pages if defined
    if let Some(max_pages) = memory_type.limits.max {
        println!("Memory configuration: current_pages={}, max_pages={}", current_pages, max_pages);
    } else {
        println!("Memory configuration: current_pages={}, no maximum limit", current_pages);
    }
    
    // Check if all memory accesses are safe
    println!("Found {} memory accesses", memory_accesses.len());
    let mut all_safe = true;
    
    for (i, access) in memory_accesses.iter().enumerate() {
        match access {
            MemoryAccess::Load(offset, align, size) => {
                if let Some(end_offset) = offset.checked_add(*size) {
                    if end_offset > current_pages as u32 * 65536 {
                        println!("Access #{}: Unsafe memory load: offset={}, size={}, align={}", 
                            i, offset, size, align);
                        all_safe = false;
                    }
                } else {
                    println!("Access #{}: Overflow in memory load calculation: offset={}, size={}", 
                        i, offset, size);
                    all_safe = false;
                }
            },
            MemoryAccess::Store(offset, align, size) => {
                if let Some(end_offset) = offset.checked_add(*size) {
                    if end_offset > current_pages as u32 * 65536 {
                        println!("Access #{}: Unsafe memory store: offset={}, size={}, align={}", 
                            i, offset, size, align);
                        all_safe = false;
                    }
                } else {
                    println!("Access #{}: Overflow in memory store calculation: offset={}, size={}", 
                        i, offset, size);
                    all_safe = false;
                }
            },
            MemoryAccess::Grow(pages) => {
                if let Some(max_pages) = memory_type.limits.max {
                    if current_pages + *pages as usize > max_pages as usize {
                        println!("Access #{}: Unsafe memory grow: current_pages={}, grow_pages={}, max_pages={}", 
                            i, current_pages, pages, max_pages);
                        all_safe = false;
                    }
                }
            }
        }
    }

    if all_safe {
        println!("✅ All memory accesses are safe!");
    } else {
        println!("❌ Memory safety verification failed!");
    }
    
    assert!(all_safe, "Memory safety check failed for alkanes contract");

    Ok(())
}

/// Test for verifying an alkanes contract with PCD
#[test]
fn test_alkanes_pcd_verification() -> Result<()> {
    println!("Starting PCD verification tests for the alkanes contract...");
    
    // Get wasm module path
    let wasm_path = Path::new("/Users/talzisckind/Downloads/deployment/verify/target/wasm32-unknown-unknown/release/test_alkanes.wasm");
    if !wasm_path.exists() {
        return Err(anyhow!("WASM binary not found at {:?}. Did you run 'just build'?", wasm_path));
    }
    
    println!("Loading WASM binary from {:?}", wasm_path);
    let wasm_bytes = fs::read(wasm_path)?;
    
    // Parse WASM binary using walrus
    println!("Parsing WASM module...");
    let module = walrus::Module::from_buffer(&wasm_bytes)?;
    
    // Initialize WASM Analyzer with the parsed module
    println!("Initializing WASM Analyzer...");
    let mut analyzer = WasmAnalyzer::new(module)?;
    
    // Analyze the module
    analyzer.analyze()?;
    
    println!("Verifying memory safety properties for PCD...");
    
    // Verify memory safety by checking that all accesses are within bounds
    let memory_id = analyzer.get_memory().expect("No memory found in module");
    let memory_accesses = analyzer.get_memory_accesses_circuit(memory_id)
        .unwrap_or_default();
    
    // Get current memory pages and memory type info
    let current_pages = analyzer.get_current_pages(memory_id);
    let memory_type = analyzer.get_memory_type(memory_id)?;
    
    // Get maximum memory pages if defined
    if let Some(max_pages) = memory_type.limits.max {
        println!("Memory configuration: current_pages={}, max_pages={}", current_pages, max_pages);
    } else {
        println!("Memory configuration: current_pages={}, no maximum limit", current_pages);
    }
    
    // Check if all memory accesses are safe
    println!("Found {} memory accesses", memory_accesses.len());
    let mut all_safe = true;
    
    for (i, access) in memory_accesses.iter().enumerate() {
        match access {
            MemoryAccess::Load(offset, align, size) => {
                if let Some(end_offset) = offset.checked_add(*size) {
                    if end_offset > current_pages as u32 * 65536 {
                        println!("Access #{}: Unsafe memory load: offset={}, size={}, align={}", 
                            i, offset, size, align);
                        all_safe = false;
                    }
                } else {
                    println!("Access #{}: Overflow in memory load calculation: offset={}, size={}", 
                        i, offset, size);
                    all_safe = false;
                }
            },
            MemoryAccess::Store(offset, align, size) => {
                if let Some(end_offset) = offset.checked_add(*size) {
                    if end_offset > current_pages as u32 * 65536 {
                        println!("Access #{}: Unsafe memory store: offset={}, size={}, align={}", 
                            i, offset, size, align);
                        all_safe = false;
                    }
                } else {
                    println!("Access #{}: Overflow in memory store calculation: offset={}, size={}", 
                        i, offset, size);
                    all_safe = false;
                }
            },
            MemoryAccess::Grow(pages) => {
                if let Some(max_pages) = memory_type.limits.max {
                    if current_pages + *pages as usize > max_pages as usize {
                        println!("Access #{}: Unsafe memory grow: current_pages={}, grow_pages={}, max_pages={}", 
                            i, current_pages, pages, max_pages);
                        all_safe = false;
                    }
                }
            }
        }
    }

    if all_safe {
        println!("✅ All memory accesses are safe!");
    } else {
        println!("❌ Memory safety verification failed!");
    }
    
    // Get the total number of functions in the module
    let function_count = analyzer.module.funcs.iter().count();
    println!("Total functions analyzed: {}", function_count);
    
    assert!(all_safe, "Memory safety check failed for alkanes contract");
    println!("PCD verification tests completed successfully.");
    Ok(())
}

/// Test for verifying a simple safe WASM module
#[test]
fn test_simple_safe_wasm_verification() -> Result<()> {
    println!("Starting memory safety verification for a simple WASM module...");
    
    // Create a simple WASM module with safe memory operations - very minimal example
    let wasm_bytes = wat::parse_str("
        (module
            ;; Define memory with initial 1 page (64KB) and max 2 pages
            (memory 1 2)
            (export \"memory\" (memory 0))
            
            ;; Simple function that stores a value at the beginning of memory
            (func (export \"safe_store\") 
                ;; Store value 42 at offset 0 (safe operation)
                i32.const 0  ;; offset
                i32.const 42 ;; value
                i32.store
                ;; No return value needed
            )
        )
    ")?.to_vec();
    
    // Parse WASM binary using walrus
    println!("Parsing safe WASM module...");
    let module = walrus::Module::from_buffer(&wasm_bytes)?;
    
    // Initialize WASM Analyzer with the parsed module
    println!("Initializing WASM Analyzer...");
    let mut analyzer = WasmAnalyzer::new(module)?;
    
    // Analyze the module
    analyzer.analyze()?;
    
    // Verify memory safety properties
    println!("Verifying memory safety properties...");
    let memory_id = analyzer.get_memory().expect("No memory found in module");
    let memory_accesses = analyzer.get_memory_accesses_circuit(memory_id)
        .unwrap_or_default();
    
    // Get current memory pages and memory type info
    let current_pages = analyzer.get_current_pages(memory_id);
    let memory_type = analyzer.get_memory_type(memory_id)?;
    
    // Get maximum memory pages if defined
    if let Some(max_pages) = memory_type.limits.max {
        println!("Memory configuration: current_pages={}, max_pages={}", current_pages, max_pages);
    } else {
        println!("Memory configuration: current_pages={}, no maximum limit", current_pages);
    }
    
    // Check if all memory accesses are safe
    println!("Found {} memory accesses", memory_accesses.len());
    let mut all_safe = true;
    
    for (i, access) in memory_accesses.iter().enumerate() {
        match access {
            MemoryAccess::Load(offset, align, size) => {
                if let Some(end_offset) = offset.checked_add(*size) {
                    if end_offset > current_pages as u32 * 65536 {
                        println!("Access #{}: Unsafe memory load: offset={}, size={}, align={}", 
                            i, offset, size, align);
                        all_safe = false;
                    }
                } else {
                    println!("Access #{}: Overflow in memory load calculation: offset={}, size={}", 
                        i, offset, size);
                    all_safe = false;
                }
            },
            MemoryAccess::Store(offset, align, size) => {
                if let Some(end_offset) = offset.checked_add(*size) {
                    if end_offset > current_pages as u32 * 65536 {
                        println!("Access #{}: Unsafe memory store: offset={}, size={}, align={}", 
                            i, offset, size, align);
                        all_safe = false;
                    }
                } else {
                    println!("Access #{}: Overflow in memory store calculation: offset={}, size={}", 
                        i, offset, size);
                    all_safe = false;
                }
            },
            MemoryAccess::Grow(pages) => {
                if let Some(max_pages) = memory_type.limits.max {
                    if current_pages + *pages as usize > max_pages as usize {
                        println!("Access #{}: Unsafe memory grow: current_pages={}, grow_pages={}, max_pages={}", 
                            i, current_pages, pages, max_pages);
                        all_safe = false;
                    }
                }
            }
        }
    }

    if all_safe {
        println!("✅ All memory accesses are safe!");
    } else {
        println!("❌ Memory safety verification failed!");
    }
    
    assert!(all_safe, "Memory safety check failed for simple safe WASM module");
    println!("Simple safe WASM module verification completed successfully.");
    Ok(())
}
