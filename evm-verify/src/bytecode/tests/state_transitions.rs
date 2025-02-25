#[cfg(test)]
mod state_transitions {
    use crate::bytecode::BytecodeAnalyzer;
    use ethers::types::{Bytes, U256};
    use hex_literal::hex;
    use anyhow::Result;

    #[test]
    fn test_state_transitions() -> Result<()> {
        let bytecode = Bytes::from(hex!(
            "6000" // PUSH1 0 - value
            "6000" // PUSH1 0 - offset
            "52"   // MSTORE - write to memory
            "6000" // PUSH1 0 - offset
            "51"   // MLOAD - read from memory
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        let analysis = analyzer.analyze()?;
        assert!(analysis.warnings.is_empty());
        Ok(())
    }

    #[test]
    fn test_complex_state_transitions() -> Result<()> {
        let bytecode = Bytes::from(hex!(
            "6000" // PUSH1 0 - value
            "6000" // PUSH1 0 - offset
            "52"   // MSTORE - write to memory
            "6020" // PUSH1 32 - size
            "6000" // PUSH1 0 - offset
            "6000" // PUSH1 0 - value
            "37"   // CALLDATACOPY - copy to memory
            "6000" // PUSH1 0 - offset
            "51"   // MLOAD - read from memory
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        let analysis = analyzer.analyze()?;
        assert!(analysis.warnings.is_empty());
        Ok(())
    }
}
