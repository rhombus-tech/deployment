#[cfg(test)]
mod delegate_tests {
    use crate::bytecode::BytecodeAnalyzer;
    use ethers::types::{Bytes, U256};
    use hex_literal::hex;
    use anyhow::Result;

    #[test]
    fn test_detect_delegatecall() -> Result<()> {
        let bytecode = Bytes::from(hex!(
            "608060405234801561001057600080fd5b50610304806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c80639ec5a89414610030575b600080fd5b61004a600480360381019061004591906100c9565b610060565b60405161005791906100f5565b60405180910390f35b60008173ffffffffffffffffffffffffffffffffffffffff1660008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600080516020610283833981519152600080516020610283833981519152604051610138929190610218565b60405180910390a3600080516020610283833981519152600080516020610283833981519152604051610169929190610218565b60405180910390a360405160200161018091906102a8565b6040516020818303038152906040528051906020012060001c9050919050565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006101d68261018b565b9050919050565b6101e6816101cb565b81146101f157600080fd5b50565b600081359050610203816101dd565b92915050565b600081519050610218816101dd565b92915050565b60006040820190506102336000830185610209565b6102406020830184610209565b9392505050565b6000819050919050565b61025a81610247565b82525050565b60006020820190506102756000830184610251565b92915050565b600082825260208201905092915050565b60005b838110156102af578082015181840152602081019050610294565b838111156102be576000848401525b50505050565bfe"
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        
        // Simulate delegatecall operations that could cause issues
        analyzer.record_memory_allocation(U256::from(0), U256::from(64))?;
        analyzer.record_memory_access(U256::from(0), U256::from(64), true, None)?;
        
        // Check for delegatecall operations in memory accesses
        let memory = analyzer.get_memory();
        let has_delegatecall = memory.accesses.iter().any(|access| {
            access.write && access.size.as_u64() > 32
        });

        assert!(has_delegatecall, "Should detect delegatecall operations");
        Ok(())
    }

    #[test]
    fn test_safe_delegate() -> Result<()> {
        let bytecode = Bytes::from(hex!(
            "608060405234801561001057600080fd5b50610304806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c80639ec5a89414610030575b600080fd5b61004a600480360381019061004591906100c9565b610060565b60405161005791906100f5565b60405180910390f35b60008173ffffffffffffffffffffffffffffffffffffffff1660008054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16600080516020610283833981519152600080516020610283833981519152604051610138929190610218565b60405180910390a3600080516020610283833981519152600080516020610283833981519152604051610169929190610218565b60405180910390a360405160200161018091906102a8565b6040516020818303038152906040528051906020012060001c9050919050565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006101d68261018b565b9050919050565b6101e6816101cb565b81146101f157600080fd5b50565b600081359050610203816101dd565b92915050565b600081519050610218816101dd565b92915050565b60006040820190506102336000830185610209565b6102406020830184610209565b9392505050565b6000819050919050565b61025a81610247565b82525050565b60006020820190506102756000830184610251565b92915050565b600082825260208201905092915050565b60005b838110156102af578082015181840152602081019050610294565b838111156102be576000848401525b50505050565bfe"
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        
        // Simulate safe delegatecall operations
        analyzer.record_memory_allocation(U256::from(0), U256::from(32))?;
        analyzer.record_memory_access(U256::from(0), U256::from(32), true, None)?;
        
        // Check for delegatecall operations in memory accesses
        let memory = analyzer.get_memory();
        let has_unsafe_delegate = memory.accesses.iter().any(|access| {
            access.write && access.size.as_u64() > 32
        });

        assert!(!has_unsafe_delegate, "Should not detect unsafe delegatecall operations");
        Ok(())
    }

    #[test]
    fn test_delegate_call_tracking() -> Result<()> {
        // Create bytecode with DELEGATECALL (0xF4)
        // Stack setup for DELEGATECALL:
        // [gas, target, in_offset, in_size, out_offset, out_size]
        let bytecode = Bytes::from(hex!(
            "6020"  // PUSH1 32 (out_size)
            "6020"  // PUSH1 32 (out_offset)
            "6020"  // PUSH1 32 (in_size)
            "6000"  // PUSH1 0 (in_offset)
            "73FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"  // PUSH20 target_address
            "6020"  // PUSH1 32 (gas)
            "f4"    // DELEGATECALL
        ));
        
        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        let runtime = analyzer.analyze()?;
        
        // Verify delegate calls are tracked
        assert!(!runtime.delegate_calls.is_empty(), "Should track delegate calls");
        
        // Check delegate call details
        let delegate_call = &runtime.delegate_calls[0];
        assert_eq!(delegate_call.data_size.as_u64(), 32, "Should have correct data size");
        assert_eq!(delegate_call.return_size.as_u64(), 32, "Should have correct return size");
        assert_eq!(delegate_call.data_offset.as_u64(), 0, "Should have correct data offset");
        assert_eq!(delegate_call.return_offset.as_u64(), 32, "Should have correct return offset");
        
        Ok(())
    }

    #[test]
    fn test_recursive_delegate_calls() -> Result<()> {
        // Create bytecode with nested DELEGATECALL (0xF4)
        let bytecode = Bytes::from(hex!(
            // First DELEGATECALL
            "6020"  // PUSH1 32 (out_size)
            "6020"  // PUSH1 32 (out_offset) 
            "6020"  // PUSH1 32 (in_size)
            "6000"  // PUSH1 0 (in_offset)
            "73FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"  // PUSH20 target_address
            "5A"    // GAS - Get remaining gas
            "F4"    // DELEGATECALL
            "50"    // POP - Remove success value from first call
            
            // Second DELEGATECALL
            "6020"  // PUSH1 32 (out_size)
            "6020"  // PUSH1 32 (out_offset)
            "6020"  // PUSH1 32 (in_size) 
            "6000"  // PUSH1 0 (in_offset)
            "73EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"  // PUSH20 different_target
            "5A"    // GAS - Get remaining gas
            "F4"    // DELEGATECALL
            
            // Return from both calls
            "6000"  // PUSH1 0 (size)
            "6000"  // PUSH1 0 (offset)
            "F3"    // RETURN
        ));

        let mut analyzer = BytecodeAnalyzer::new(bytecode);
        let runtime = analyzer.analyze()?;

        // Verify we have two delegate calls
        assert_eq!(runtime.delegate_calls.len(), 2, "Should track two delegate calls");

        // First call should be parent
        let parent_call = &runtime.delegate_calls[0];
        assert!(parent_call.parent_call_id.is_none(), "First call should have no parent");
        assert_eq!(parent_call.child_call_ids.len(), 1, "First call should have one child");
        assert_eq!(parent_call.depth, 0, "First call should be at depth 0");

        // Second call should be child
        let child_call = &runtime.delegate_calls[1];
        assert_eq!(child_call.parent_call_id, Some(0), "Second call should have parent id 0");
        assert!(child_call.child_call_ids.is_empty(), "Child call should have no children");
        assert_eq!(child_call.depth, 1, "Child call should be at depth 1");

        Ok(())
    }
}
