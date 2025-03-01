#[cfg(test)]
mod tests {
    use crate::analyzer::{
        pipeline::AnalysisPipeline,
        memory::MemorySafetyProperty,
        bytecode::BytecodeSafetyProperty,
        Property,
    };
    use crate::circuits::{
        memory::MemorySafetyCircuit,
        bytecode::BytecodeSafetyCircuit,
    };
    use crate::prover::{
        generate_proving_key,
        generate_proof,
        verify_memory_proof,
        verify_bytecode_proof,
    };
    use ark_bls12_381::Fr;
    use ark_relations::r1cs::ConstraintSynthesizer;
    
    // Sample EVM bytecode for testing
    // This is a simple contract that performs a basic storage operation
    const SAMPLE_BYTECODE: &[u8] = &[
        // PUSH1 0x80 (stack init)
        0x60, 0x80, 
        // PUSH1 0x40 (free memory pointer)
        0x60, 0x40, 
        // MSTORE
        0x52,
        // CALLVALUE
        0x34,
        // DUP1
        0x80,
        // ISZERO
        0x15,
        // PUSH1 0x0f (jump dest if zero)
        0x60, 0x0f,
        // JUMPI
        0x57,
        // PUSH1 0x00
        0x60, 0x00,
        // DUP1
        0x80,
        // REVERT
        0xfd,
        // JUMPDEST
        0x5b,
        // POP
        0x50,
        // PUSH1 0x01 (value to store)
        0x60, 0x01,
        // PUSH1 0x00 (storage slot)
        0x60, 0x00,
        // SSTORE (store value in storage)
        0x55,
        // STOP
        0x00
    ];
    
    // Sample vulnerable bytecode with reentrancy
    const VULNERABLE_BYTECODE: &[u8] = &[
        // PUSH1 0x80 (stack init)
        0x60, 0x80, 
        // PUSH1 0x40 (free memory pointer)
        0x60, 0x40, 
        // MSTORE
        0x52,
        // CALLVALUE
        0x34,
        // DUP1
        0x80,
        // ISZERO
        0x15,
        // PUSH1 0x0f (jump dest if zero)
        0x60, 0x0f,
        // JUMPI
        0x57,
        // PUSH1 0x00
        0x60, 0x00,
        // DUP1
        0x80,
        // REVERT
        0xfd,
        // JUMPDEST
        0x5b,
        // POP
        0x50,
        // PUSH1 0x00 (gas)
        0x60, 0x00,
        // PUSH1 0x01 (address)
        0x60, 0x01,
        // PUSH1 0x00 (value)
        0x60, 0x00,
        // PUSH1 0x00 (in offset)
        0x60, 0x00,
        // PUSH1 0x00 (in size)
        0x60, 0x00,
        // PUSH1 0x00 (out offset)
        0x60, 0x00,
        // PUSH1 0x00 (out size)
        0x60, 0x00,
        // CALL (external call without checks)
        0xf1,
        // PUSH1 0x01 (value to store)
        0x60, 0x01,
        // PUSH1 0x00 (storage slot)
        0x60, 0x00,
        // SSTORE (store value in storage after call)
        0x55,
        // STOP
        0x00
    ];
    
    #[test]
    fn test_memory_safety_property() {
        let property = MemorySafetyProperty;
        let result = property.verify(SAMPLE_BYTECODE);
        assert!(result.is_ok());
        
        let proof_data = result.unwrap();
        assert!(proof_data.bounds_checked);
        assert!(proof_data.leak_free);
        assert!(proof_data.access_safety);
    }
    
    #[test]
    fn test_bytecode_safety_property() {
        let property = BytecodeSafetyProperty;
        
        // Test safe bytecode
        let result = property.verify(SAMPLE_BYTECODE);
        assert!(result.is_ok());
        let proof_data = result.unwrap();
        assert!(proof_data.is_safe);
        assert!(proof_data.vulnerabilities.is_empty());
        
        // Test vulnerable bytecode
        let result = property.verify(VULNERABLE_BYTECODE);
        assert!(result.is_ok());
        let proof_data = result.unwrap();
        assert!(!proof_data.is_safe);
        assert!(!proof_data.vulnerabilities.is_empty());
    }
    
    #[test]
    fn test_analysis_pipeline() {
        let mut pipeline = AnalysisPipeline::new();
        
        // Test safe bytecode
        let result = pipeline.analyze(SAMPLE_BYTECODE);
        assert!(result.is_ok());
        assert!(pipeline.is_safe());
        
        // Test vulnerable bytecode
        let mut pipeline = AnalysisPipeline::new();
        let result = pipeline.analyze(VULNERABLE_BYTECODE);
        assert!(result.is_ok());
        assert!(!pipeline.is_safe());
        
        // Print analysis summary
        println!("{}", pipeline.get_summary());
    }
    
    #[test]
    fn test_memory_safety_circuit() {
        // Create a simple memory safety circuit
        let accesses = vec![
            (ethers::types::U256::from(0), ethers::types::U256::from(32)),
            (ethers::types::U256::from(32), ethers::types::U256::from(32)),
        ];
        
        let allocations = vec![
            (ethers::types::U256::from(0), ethers::types::U256::from(64)),
        ];
        
        let circuit = MemorySafetyCircuit::<Fr>::new(accesses, allocations);
        
        // Generate proving key
        let result = generate_proving_key(&circuit);
        assert!(result.is_ok());
        
        // In a real test, we would also generate and verify proofs
    }
    
    #[test]
    fn test_bytecode_safety_circuit() {
        // Create a simple bytecode safety circuit
        let vulnerabilities = vec![];
        let gas_usage = ethers::types::U256::from(1000);
        let complexity = 5;
        
        let circuit = BytecodeSafetyCircuit::<Fr>::new(&vulnerabilities, gas_usage, complexity);
        
        // Generate proving key
        let result = generate_proving_key(&circuit);
        assert!(result.is_ok());
        
        // In a real test, we would also generate and verify proofs
    }
}
