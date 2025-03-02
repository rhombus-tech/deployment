#[cfg(feature = "accumulation")]
mod tests {
    use anyhow::Result;
    use ark_bn254::Fr;
    use ark_std::rand::thread_rng;
    use ethers::types::Bytes;
    use evm_verify::pcd::evm_accumulation::{
        EVMBytecodeInput,
        generate_evm_proof,
        verify_evm_proof,
        serialize_proof,
        deserialize_proof,
        accumulate_proofs,
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
        let is_valid = verify_evm_proof(bytecode, &proof, &vk, curr_state)?;
        
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
        let input = EVMBytecodeInput {
            bytecode,
            prev_state: None,
            curr_state,
        };
        
        // Check that the input was created successfully
        assert!(!input.bytecode.is_empty(), "Input bytecode should not be empty");
        assert!(!input.curr_state.is_empty(), "Input curr_state should not be empty");
        
        Ok(())
    }

    #[test]
    fn test_proof_accumulation() -> Result<()> {
        // Create dummy bytecodes
        let bytecode1 = Bytes::from(vec![0x01, 0x02, 0x03]);
        let bytecode2 = Bytes::from(vec![0x04, 0x05, 0x06]);
        
        // Create dummy states
        let curr_state1 = vec![Fr::from(1u32), Fr::from(2u32)];
        let curr_state2 = vec![Fr::from(3u32), Fr::from(4u32)];
        
        // Generate proofs
        let mut rng = thread_rng();
        let (proof1, _) = generate_evm_proof(bytecode1.clone(), None, curr_state1.clone(), &mut rng)?;
        let (proof2, _) = generate_evm_proof(bytecode2.clone(), None, curr_state2.clone(), &mut rng)?;
        
        // Accumulate proofs
        let proofs = vec![proof1, proof2];
        let public_inputs = vec![curr_state1, curr_state2];
        let result = accumulate_proofs(proofs, public_inputs, &mut rng);
        
        assert!(result.is_ok(), "Proof accumulation should succeed");
        
        Ok(())
    }
}
