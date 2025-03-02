#[cfg(feature = "accumulation")]
mod tests {
    use anyhow::Result;
    use ethers::types::Bytes;
    use ark_bn254::Fr;
    use ark_std::rand::thread_rng;
    
    use evm_verify::api::unified::UnifiedVerifier;
    use evm_verify::api::PCDAdapter;
    
    #[test]
    fn test_accumulation_pcd() -> Result<()> {
        // Create a unified verifier
        let verifier = UnifiedVerifier::new();
        
        // Create a simple bytecode
        let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]); // PUSH1 1 PUSH1 0 SSTORE
        
        // Analyze the bytecode
        let report = verifier.analyze_bytecode(bytecode.clone())?;
        
        // Check that we got a report
        assert!(report.timestamp > 0);
        
        Ok(())
    }
    
    #[test]
    fn test_pcd_adapter() -> Result<()> {
        // Create a PCD adapter
        let adapter = PCDAdapter::new();
        
        // Create a simple bytecode
        let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]); // PUSH1 1 PUSH1 0 SSTORE
        
        // Verify the bytecode
        let result = adapter.verify_bytecode(bytecode)?;
        
        // Check that the bytecode is valid
        assert!(result.is_valid);
        
        Ok(())
    }
}

#[cfg(not(feature = "accumulation"))]
mod tests {
    #[test]
    fn test_dummy() {
        // This test is skipped when accumulation is not enabled
        assert!(true);
    }
}
