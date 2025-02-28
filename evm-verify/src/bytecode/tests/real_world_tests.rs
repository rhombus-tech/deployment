#[cfg(test)]
mod real_world_tests {
    use crate::bytecode::BytecodeAnalyzer;
    use ethers::types::{Bytes, U256};
    use hex_literal::hex;
    use anyhow::Result;

    #[test]
    fn test_real_world_contract() -> Result<()> {
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
            "6001" // PUSH1 1
            "16"   // AND - bitwise AND
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        analyzer.set_test_mode(true);
        let analysis = analyzer.analyze()?;
        assert!(analysis.warnings.is_empty());
        Ok(())
    }

    #[test]
    fn test_complex_contract() -> Result<()> {
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
            "6001" // PUSH1 1
            "16"   // AND - bitwise AND
            "6002" // PUSH1 2
            "17"   // OR - bitwise OR
            "6003" // PUSH1 3
            "18"   // XOR - bitwise XOR
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        analyzer.set_test_mode(true);
        let analysis = analyzer.analyze()?;
        assert!(analysis.warnings.is_empty());
        Ok(())
    }
}
