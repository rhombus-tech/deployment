#[cfg(test)]
mod arithmetic_tests {
    use crate::bytecode::BytecodeAnalyzer;
    use ethers::types::{Bytes, U256};
    use hex_literal::hex;
    use anyhow::Result;

    #[test]
    fn test_detect_overflow() -> Result<()> {
        // Create bytecode that will cause arithmetic overflow
        // Push max U256 value and 1, then add them to cause overflow
        let bytecode = Bytes::from(hex!(
            "7f" // PUSH32
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" // max U256 value
            "6001" // PUSH1 1
            "01"   // ADD - This will cause overflow
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        let analysis = analyzer.analyze()?;
        assert!(!analysis.warnings.is_empty());
        Ok(())
    }

    #[test]
    fn test_safe_arithmetic() -> Result<()> {
        let bytecode = Bytes::from(hex!(
            "6001" // PUSH1 1
            "6002" // PUSH1 2
            "01"   // ADD - Safe arithmetic
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        analyzer.set_test_mode(true);
        let analysis = analyzer.analyze()?;
        assert!(analysis.warnings.is_empty());
        Ok(())
    }
}
