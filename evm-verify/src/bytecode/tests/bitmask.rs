#[cfg(test)]
mod bitmask_tests {
    use crate::bytecode::BytecodeAnalyzer;
    use ethers::types::{Bytes, U256};
    use hex_literal::hex;
    use anyhow::Result;

    #[test]
    fn test_detect_bitmask() -> Result<()> {
        // Create bytecode that uses a bitmask
        let bytecode = Bytes::from(hex!(
            "6001" // PUSH1 1 - value
            "6020" // PUSH1 32 - size
            "6000" // PUSH1 0 - offset
            "52"   // MSTORE - write initial value
            "6020" // PUSH1 32 - size
            "6000" // PUSH1 0 - offset
            "51"   // MLOAD - read value
            "6001" // PUSH1 1 - bitmask
            "16"   // AND - apply bitmask
            "6020" // PUSH1 32 - size
            "6000" // PUSH1 0 - offset
            "52"   // MSTORE - store result
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        analyzer.set_test_mode(true);
        let analysis = analyzer.analyze()?;
        assert!(analysis.warnings.is_empty());
        Ok(())
    }

    #[test]
    fn test_safe_bitmask() -> Result<()> {
        // Create bytecode that uses safe bitmask operations
        let bytecode = Bytes::from(hex!(
            "6001" // PUSH1 1 - value
            "6020" // PUSH1 32 - size
            "6000" // PUSH1 0 - offset
            "52"   // MSTORE - write initial value
            "6020" // PUSH1 32 - size
            "6000" // PUSH1 0 - offset
            "51"   // MLOAD - read value
            "6001" // PUSH1 1 - bitmask
            "17"   // OR - apply bitmask
            "6020" // PUSH1 32 - size
            "6000" // PUSH1 0 - offset
            "52"   // MSTORE - store result
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        analyzer.set_test_mode(true);
        let analysis = analyzer.analyze()?;
        assert!(analysis.warnings.is_empty());
        Ok(())
    }

    #[test]
    fn test_detect_bitmask_complex() -> Result<()> {
        // Create bytecode that uses multiple bitmask operations
        let bytecode = Bytes::from(hex!(
            "6001" // PUSH1 1 - value
            "6020" // PUSH1 32 - size
            "6000" // PUSH1 0 - offset
            "52"   // MSTORE - write initial value
            "6020" // PUSH1 32 - size
            "6000" // PUSH1 0 - offset
            "51"   // MLOAD - read value
            "6001" // PUSH1 1 - first bitmask
            "16"   // AND - apply first bitmask
            "6002" // PUSH1 2 - second bitmask
            "17"   // OR - apply second bitmask
            "6003" // PUSH1 3 - third bitmask
            "18"   // XOR - apply third bitmask
            "6020" // PUSH1 32 - size
            "6000" // PUSH1 0 - offset
            "52"   // MSTORE - store final result
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        analyzer.set_test_mode(true);
        let analysis = analyzer.analyze()?;
        assert!(analysis.warnings.is_empty());
        Ok(())
    }

    #[test]
    fn test_safe_bitmask_complex() -> Result<()> {
        // Create bytecode that uses safe complex bitmask operations
        let bytecode = Bytes::from(hex!(
            "6001" // PUSH1 1 - value
            "6020" // PUSH1 32 - size
            "6000" // PUSH1 0 - offset
            "52"   // MSTORE - write initial value
            "6020" // PUSH1 32 - size
            "6000" // PUSH1 0 - offset
            "51"   // MLOAD - read value
            "6001" // PUSH1 1 - first bitmask
            "17"   // OR - apply first bitmask
            "6002" // PUSH1 2 - second bitmask
            "16"   // AND - apply second bitmask
            "6003" // PUSH1 3 - third bitmask
            "18"   // XOR - apply third bitmask
            "6020" // PUSH1 32 - size
            "6000" // PUSH1 0 - offset
            "52"   // MSTORE - store final result
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        analyzer.set_test_mode(true);
        let analysis = analyzer.analyze()?;
        assert!(analysis.warnings.is_empty());
        Ok(())
    }
}
