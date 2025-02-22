#[cfg(test)]
mod tests {
    use super::*;
    use ethers::types::Bytes;
    use hex_literal::hex;

    #[test]
    fn test_simple_contract_analysis() -> Result<()> {
        // Simple contract bytecode (constructor that sets owner)
        let bytecode = Bytes::from(hex!(
            "608060405234801561001057600080fd5b50336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff
             021916908373ffffffffffffffffffffffffffffffffffffffff160217905550610150806100606000396000f3fe608060
             405234801561001057600080fd5b506004361061002b5760003560e01c8063893d20e814610030575b600080fd5b6100
             386100c6565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffff
             ffffffff16815260200191505060405180910390f35b60008060009054906101000a900473ffffffffffffffffffffffff
             ffffffffffffffffff16905090565b"
        ));

        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        let results = analyzer.analyze()?;

        // Verify constructor analysis
        assert!(results.constructor.args_length == 0, "No constructor args expected");
        
        // Verify runtime analysis
        assert!(!results.runtime.init_slots.is_empty(), "Should find storage initialization");
        
        // Verify access patterns
        let patterns = &results.runtime.access_patterns;
        assert!(!patterns.is_empty(), "Should find access control patterns");
        
        // Verify owner slot is protected
        let owner_pattern = patterns.iter()
            .find(|p| p.condition.contains("owner"))
            .expect("Should find owner access pattern");
        
        assert!(owner_pattern.condition.contains("msg.sender"), 
            "Owner check should compare against msg.sender");

        Ok(())
    }

    #[test]
    fn test_constructor_args_analysis() -> Result<()> {
        // Contract with constructor arguments (uint256 _value)
        let bytecode = Bytes::from(hex!(
            "608060405234801561001057600080fd5b506040516101a93803806101a983398181016040526020811015610032576000
             80fd5b810190808051906020019092919050505080600081905550336000806101000a81548173ffffffffffffffffffffffff
             ffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550506101168061009a6000
             396000f3fe"
        ));

        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        let results = analyzer.analyze()?;

        // Verify constructor args
        assert!(results.constructor.args_length > 0, "Should have constructor args");
        assert!(results.constructor.param_types.contains(&"uint256".to_string()),
            "Should detect uint256 parameter");

        Ok(())
    }
}
