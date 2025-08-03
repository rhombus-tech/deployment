#[cfg(test)]
mod tests {
    use crate::bytecode::analyzer::BytecodeAnalyzer;
    use ethers::types::Bytes;
    use ethers::types::U256;
    use anyhow::Result;

    #[test]
    fn test_calldataload_opcode() -> Result<()> {
        // Create a simple bytecode that just does CALLDATALOAD from offset 0
        let opcodes = vec![0x35]; // CALLDATALOAD
        let bytes = Bytes::from(opcodes);
        
        // Create and initialize the analyzer
        let mut analyzer = BytecodeAnalyzer::new(bytes);
        analyzer.set_test_mode(true);
        
        // Push an offset value of 0 to the stack
        analyzer.state.stack.push(U256::zero());
        
        // Execute the opcode at the current position
        analyzer.analyze_code_sections()?;
        
        // Check that the stack now contains the function selector placeholder
        assert_eq!(analyzer.state.stack.len(), 1);
        let result = analyzer.state.stack.pop().unwrap();
        
        // Print out the result for debugging
        println!("CALLDATALOAD result: {:x}", result);
        
        // The first 4 bytes should be 0xCAFE0000
        let expected = U256::from_str_radix("CAFE0000000000000000000000000000000000000000000000000000000000000000", 16).unwrap();
        assert_eq!(result, expected);
        
        Ok(())
    }
}
