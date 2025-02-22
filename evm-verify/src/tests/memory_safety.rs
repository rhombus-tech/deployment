use crate::{
    bytecode::{
        memory::MemoryAnalyzer,
        types::{MemoryAccess, MemoryAllocation},
    },
    circuits::memory::MemorySafetyCircuit,
};

use anyhow::Result;
use ethers::types::U256;

#[test]
fn test_memory_analyzer() -> Result<()> {
    let mut analyzer = MemoryAnalyzer::new();

    // Test safe memory access
    let safe_access = MemoryAccess {
        offset: U256::from(0),
        size: U256::from(32),
        pc: 0,
        write: true,
    };

    analyzer.record_access(safe_access.offset, safe_access.size, safe_access.pc, safe_access.write);

    // Test safe memory allocation
    let safe_alloc = MemoryAllocation {
        offset: U256::from(0),
        size: U256::from(64),
        pc: 0,
    };

    analyzer.record_allocation(safe_alloc.offset, safe_alloc.size, safe_alloc.pc);

    Ok(())
}

#[test]
fn test_memory_safety_circuit() -> Result<()> {
    // Safe bytecode with valid memory accesses
    let safe_bytecode = vec![
        0x52, // MSTORE
        0x00, // offset = 0
        0x51, // MLOAD
        0x20, // offset = 32
    ];

    // Unsafe bytecode with invalid memory accesses
    let unsafe_bytecode = vec![
        0x52, // MSTORE
        0xff, // offset = 255 (too large)
        0x51, // MLOAD
        0xff, // offset = 255 (too large)
    ];

    // Complex bytecode with multiple memory operations
    let complex_bytecode = vec![
        0x52, // MSTORE
        0x00, // offset = 0
        0x51, // MLOAD
        0x20, // offset = 32
        0x53, // MSTORE8
        0x40, // offset = 64
        0x37, // CALLDATACOPY
        0x60, // destOffset = 96
        0x00, // offset = 0
        0x20, // size = 32
    ];

    // Test safe bytecode
    let mut analyzer = MemoryAnalyzer::new();
    let analysis = analyzer.analyze(&safe_bytecode)?;
    assert!(!analysis.memory_accesses.is_empty());

    // Test unsafe bytecode
    let mut analyzer = MemoryAnalyzer::new();
    let analysis = analyzer.analyze(&unsafe_bytecode)?;
    assert!(!analysis.memory_accesses.is_empty());

    // Test complex bytecode
    let mut analyzer = MemoryAnalyzer::new();
    let analysis = analyzer.analyze(&complex_bytecode)?;
    assert!(!analysis.memory_accesses.is_empty());
    assert!(!analysis.memory_allocations.is_empty());

    Ok(())
}

#[test]
fn test_memory_safety_verification() -> Result<()> {
    // Test bytecode with different memory access patterns
    let test_cases = vec![
        // Safe bytecode
        vec![
            0x52, // MSTORE
            0x00, // offset = 0
            0x51, // MLOAD
            0x20, // offset = 32
        ],
        
        // Unsafe bytecode
        vec![
            0x52, // MSTORE
            0xff, // offset = 255 (too large)
            0x51, // MLOAD
            0xff, // offset = 255 (too large)
        ],
        
        // Complex bytecode
        vec![
            0x52, // MSTORE
            0x00, // offset = 0
            0x51, // MLOAD
            0x20, // offset = 32
            0x53, // MSTORE8
            0x40, // offset = 64
            0x37, // CALLDATACOPY
            0x60, // destOffset = 96
            0x00, // offset = 0
            0x20, // size = 32
        ],
    ];

    for bytecode in test_cases {
        let mut analyzer = MemoryAnalyzer::new();
        let analysis = analyzer.analyze(&bytecode)?;
        assert!(!analysis.memory_accesses.is_empty());
    }

    Ok(())
}
