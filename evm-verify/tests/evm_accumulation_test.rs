#[cfg(feature = "accumulation")]
mod tests {
    use anyhow::Result;
    use ark_bn254::Fr;
    use ark_std::rand::thread_rng;
    use ethers::types::Bytes;
    use evm_verify::pcd::evm_accumulation::{
        EVMBytecodeInput,
        create_evm_input,
        generate_evm_proof,
        verify_evm_proof,
        serialize_proof,
        deserialize_proof,
    };

    #[test]
    fn test_evm_proof_generation_and_verification() -> Result<()> {
        // Create a dummy bytecode
        let bytecode = Bytes::from(vec![0u8; 32]);
        
        // Create a dummy state
        let curr_state = vec![Fr::from(1u32), Fr::from(2u32), Fr::from(3u32)];
        
        // Generate a proof
        let mut rng = thread_rng();
        let (proof, vk) = generate_evm_proof(bytecode.clone(), None, curr_state.clone(), &mut rng)?;
        
        // Verify the proof
        let public_inputs = curr_state.clone();
        let is_valid = verify_evm_proof(&proof, &vk, &public_inputs)?;
        
        assert!(is_valid, "Proof verification should succeed");
        
        Ok(())
    }
    
    #[test]
    fn test_evm_proof_serialization() -> Result<()> {
        // Create a dummy bytecode
        let bytecode = Bytes::from(vec![0u8; 32]);
        
        // Create a dummy state
        let curr_state = vec![Fr::from(1u32), Fr::from(2u32), Fr::from(3u32)];
        
        // Generate a proof
        let mut rng = thread_rng();
        let (proof, _) = generate_evm_proof(bytecode, None, curr_state, &mut rng)?;
        
        // Serialize the proof
        let serialized_proof = serialize_proof(&proof)?;
        
        // Deserialize the proof
        let deserialized_proof = deserialize_proof(&serialized_proof)?;
        
        // Serialize both proofs again to compare them
        let original_serialized = serialize_proof(&proof)?;
        let deserialized_serialized = serialize_proof(&deserialized_proof)?;
        
        assert_eq!(original_serialized, deserialized_serialized, "Serialized proofs should be identical");
        
        Ok(())
    }
    
    #[test]
    fn test_evm_input_creation() -> Result<()> {
        // Create a dummy bytecode
        let bytecode = Bytes::from(vec![0u8; 32]);
        
        // Create a dummy state
        let curr_state = vec![Fr::from(1u32), Fr::from(2u32), Fr::from(3u32)];
        
        // Create an input
        let input = create_evm_input(bytecode, None, curr_state)?;
        
        // Check that the input was created successfully
        assert!(input.instance().is_some(), "Input instance should be created");
        assert!(input.witness().is_some(), "Input witness should be created");
        
        Ok(())
    }
}
