#[cfg(test)]
mod real_world_tests {
    use crate::bytecode::BytecodeAnalyzer;
    use ethers::types::U256;
    use anyhow::Result;

    #[test]
    fn test_dao_hack_vulnerability() -> Result<()> {
        let mut analyzer = BytecodeAnalyzer::new();
        
        // Simulate the DAO's vulnerable withdraw pattern
        // 1. Read state before external call
        analyzer.record_memory_allocation(U256::from(0), U256::from(32))?;
        analyzer.record_memory_access(U256::from(0), U256::from(32), false)?; // Read operation
        
        // 2. External call with value transfer
        analyzer.record_memory_allocation(U256::from(32), U256::from(32))?;
        analyzer.record_memory_access(U256::from(32), U256::from(32), false)?; // External call
        
        // 3. State update after external call
        analyzer.record_memory_allocation(U256::from(64), U256::from(32))?;
        analyzer.record_memory_access(U256::from(64), U256::from(32), true)?; // Write operation

        // Get memory analyzer and check for vulnerabilities
        let memory = analyzer.get_memory();
        
        // Check for reentrancy vulnerability
        assert!(memory.has_reentrancy_vulnerability(), "Should detect DAO's reentrancy vulnerability pattern");
        
        // Get detailed vulnerability report
        let vulnerabilities = memory.get_vulnerability_report();
        assert!(!vulnerabilities.is_empty(), "Should generate vulnerability report");
        assert!(vulnerabilities[0].contains("Reentrancy"), "Report should identify reentrancy vulnerability");
        
        Ok(())
    }
}
