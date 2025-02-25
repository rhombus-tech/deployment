#[cfg(test)]
mod memory_patterns {
    use crate::bytecode::BytecodeAnalyzer;
    use ethers::types::{Bytes, U256};
    use hex_literal::hex;
    use anyhow::Result;

    #[test]
    fn test_memory_read_before_write() -> Result<()> {
        // Create bytecode that reads memory before writing
        let bytecode = Bytes::from(hex!(
            "6000" // PUSH1 0 - offset
            "51"   // MLOAD - read from memory
            "6000" // PUSH1 0 - value
            "52"   // MSTORE - write to memory
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        let analysis = analyzer.analyze()?;
        
        // Should warn about reading uninitialized memory
        assert!(!analysis.warnings.is_empty());
        Ok(())
    }

    #[test]
    fn test_safe_memory_pattern() -> Result<()> {
        // Create bytecode that writes before reading
        let bytecode = Bytes::from(hex!(
            "6000" // PUSH1 0 - value
            "6000" // PUSH1 0 - offset
            "52"   // MSTORE - write to memory
            "6000" // PUSH1 0 - offset
            "51"   // MLOAD - read from memory
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        let analysis = analyzer.analyze()?;
        
        // Should not warn about memory access
        assert!(analysis.warnings.is_empty());
        Ok(())
    }

    #[test]
    fn test_memory_bounds() -> Result<()> {
        // Create bytecode that accesses memory out of bounds
        let bytecode = Bytes::from(hex!(
            "6020" // PUSH1 32 - size
            "6000" // PUSH1 0 - offset
            "6000" // PUSH1 0 - value
            "37"   // CALLDATACOPY - copy to memory
            "6040" // PUSH1 64 - try to read beyond written memory
            "51"   // MLOAD - read from memory
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        let analysis = analyzer.analyze()?;
        
        // Should warn about out of bounds memory access
        assert!(!analysis.warnings.is_empty());
        Ok(())
    }
}
