use crate::bytecode::BytecodeAnalyzer;
use ethers::types::Bytes;
use hex_literal::hex;
use anyhow::Result;

#[cfg(test)]
mod arithmetic;
#[cfg(test)]
mod bitmask;
#[cfg(test)]
mod delegate;
#[cfg(test)]
mod reentrancy;
#[cfg(test)]
mod solidity_checks;
#[cfg(test)]
mod real_world_tests;
#[cfg(test)]
mod state_transitions;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytecode_analyzer() -> Result<()> {
        let bytecode = Bytes::from(hex!(
            "6080604052348015600f57600080fd5b506004361060285760003560e01c8063771602f714602d575b600080fd5b60436004803603810190603f91906075565b6057565b60405160529190608c565b60405180910390f35b6000818301905092915050565b6000813590506070816099565b92915050565b6000806040838503121560845760838160a2565b5b6000608f85828601605f565b92505050919050565b60978160b7565b82525050565b6000602082019050608c6000830184608e565b92915050565b6000819050919050565b600080fd5b60be8160a2565b8114609357600080fd5b50565b"
        ));
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        analyzer.set_test_mode(true);
        let analysis = analyzer.analyze()?;
        assert!(analysis.memory_accesses.is_empty());
        Ok(())
    }
    
    #[test]
    fn test_test_mode_feature() -> Result<()> {
        let bytecode = Bytes::from(hex!(
            "6080604052348015600f57600080fd5b506004361060285760003560e01c8063771602f714602d575b600080fd5b60436004803603810190603f91906075565b6057565b60405160529190608c565b60405180910390f35b6000818301905092915050565b6000813590506070816099565b92915050565b6000806040838503121560845760838160a2565b5b6000608f85828601605f565b92505050919050565b60978160b7565b82525050565b6000602082019050608c6000830184608e565b92915050565b6000819050919050565b600080fd5b60be8160a2565b8114609357600080fd5b50565b"
        ));
        
        // Test with test_mode = true (should have empty memory_accesses)
        let mut analyzer_test_mode = BytecodeAnalyzer::new(bytecode.clone());
        analyzer_test_mode.set_test_mode(true);
        let analysis_test_mode = analyzer_test_mode.analyze()?;
        assert!(analysis_test_mode.memory_accesses.is_empty(), 
                "Memory accesses should be empty when test_mode is true");
        
        // Test with test_mode = false (should have memory_accesses)
        let mut analyzer_normal = BytecodeAnalyzer::new(bytecode);
        analyzer_normal.set_test_mode(false);
        let analysis_normal = analyzer_normal.analyze()?;
        assert!(!analysis_normal.memory_accesses.is_empty(), 
                "Memory accesses should not be empty when test_mode is false");
        
        Ok(())
    }
}
