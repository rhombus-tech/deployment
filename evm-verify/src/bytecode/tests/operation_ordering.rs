#[cfg(test)]
mod operation_ordering {
    use crate::bytecode::BytecodeAnalyzer;
    use ethers::types::{Bytes, U256};
    use hex_literal::hex;
    use anyhow::Result;

    #[test]
    fn test_invalid_operation_sequence() -> Result<()> {
        // Create bytecode with invalid operation sequence:
        // Trying to pop from empty stack
        let bytecode = Bytes::from(hex!(
            "50" // POP - trying to pop from empty stack
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        let analysis = analyzer.analyze()?;
        
        // Should warn about invalid operation sequence
        assert!(!analysis.warnings.is_empty());
        Ok(())
    }

    #[test]
    fn test_safe_operation_sequence() -> Result<()> {
        // Create bytecode with valid operation sequence
        let bytecode = Bytes::from(hex!(
            "6001" // PUSH1 1 - push value onto stack
            "50"   // POP - pop value from stack
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        let analysis = analyzer.analyze()?;
        
        // Should not warn about operation sequence
        assert!(analysis.warnings.is_empty());
        Ok(())
    }

    #[test]
    fn test_complex_operation_sequence() -> Result<()> {
        // Create bytecode with complex but valid operation sequence
        let bytecode = Bytes::from(hex!(
            "6001" // PUSH1 1
            "6002" // PUSH1 2
            "01"   // ADD
            "6000" // PUSH1 0
            "52"   // MSTORE
            "6020" // PUSH1 32
            "6000" // PUSH1 0
            "F3"   // RETURN
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        let analysis = analyzer.analyze()?;
        
        // Should not warn about operation sequence
        assert!(analysis.warnings.is_empty());
        Ok(())
    }

    #[test]
    fn test_invalid_stack_manipulation() -> Result<()> {
        // Create bytecode that tries to access stack items that don't exist
        let bytecode = Bytes::from(hex!(
            "6001" // PUSH1 1
            "80"   // DUP1
            "80"   // DUP1
            "91"   // SWAP2 - trying to swap with non-existent stack item
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        let analysis = analyzer.analyze()?;
        
        // Should warn about invalid stack manipulation
        assert!(!analysis.warnings.is_empty());
        Ok(())
    }
}
