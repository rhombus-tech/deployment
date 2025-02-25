#[cfg(test)]
mod reentrancy_tests {
    use crate::bytecode::BytecodeAnalyzer;
    use ethers::types::{Bytes, U256};
    use hex_literal::hex;
    use anyhow::Result;

    #[test]
    fn test_detect_reentrancy() -> Result<()> {
        // Create bytecode that simulates a reentrancy vulnerability
        // Pattern: read state -> external call -> write state
        let bytecode = Bytes::from(hex!(
            "6000" // PUSH1 0
            "54"   // SLOAD - read from storage
            "5A"   // GAS - prepare for call
            "6000" // PUSH1 0 - value for call
            "6000" // PUSH1 0 - target address
            "F1"   // CALL - external call
            "6000" // PUSH1 0
            "55"   // SSTORE - write to storage after call
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        let analysis = analyzer.analyze()?;
        assert!(!analysis.warnings.is_empty());
        Ok(())
    }

    #[test]
    fn test_safe_reentrancy() -> Result<()> {
        // Create bytecode for a safe contract
        // Pattern: write state -> external call
        let bytecode = Bytes::from(hex!(
            "6000" // PUSH1 0
            "6001" // PUSH1 1
            "55"   // SSTORE - write to storage first
            "5A"   // GAS - prepare for call
            "6000" // PUSH1 0 - value for call
            "6000" // PUSH1 0 - target address
            "F1"   // CALL - external call after state changes
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        let analysis = analyzer.analyze()?;
        assert!(analysis.warnings.is_empty());
        Ok(())
    }
}
