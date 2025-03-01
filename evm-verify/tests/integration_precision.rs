#[cfg(test)]
mod tests {
    use evm_verify::circuits::precision::PrecisionCircuit;
    use evm_verify::circuits::CircuitBuilder;
    use evm_verify::common::DeploymentData;
    use evm_verify::bytecode::analyzer::BytecodeAnalyzer;
    use evm_verify::api::{EVMVerify, ConfigManager};
    use ethers::types::{Bytes, H160};
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_ff::PrimeField;

    // Helper function to create a test circuit with the given bytecode
    fn create_test_circuit<F: PrimeField>(bytecode: &[u8]) -> PrecisionCircuit<F> {
        // Create a bytecode analyzer
        let analyzer = BytecodeAnalyzer::new(Bytes::from(bytecode.to_vec()));
        
        // Create deployment data
        let deployment_data = DeploymentData {
            owner: H160::zero(),
        };
        
        // Create a circuit builder
        let circuit_builder = CircuitBuilder::<F>::new(deployment_data, Default::default());
        
        // Build the precision circuit
        circuit_builder.build_precision()
    }

    #[test]
    fn test_integration_precision_circuit() {
        // Simple bytecode with a division before multiplication vulnerability
        // PUSH1 10 (amount)
        // PUSH1 100 (total)
        // DIV
        // PUSH1 20 (ratio)
        // MUL
        let vulnerable_bytecode = vec![
            0x60, 0x0a, // PUSH1 10 (amount)
            0x60, 0x64, // PUSH1 100 (total)
            0x04,       // DIV
            0x60, 0x14, // PUSH1 20 (ratio)
            0x02,       // MUL
        ];
        
        // Create the circuit
        let circuit = create_test_circuit::<ark_bn254::Fr>(&vulnerable_bytecode);
        
        // Test integration with the API
        let config = ConfigManager::builder()
            .detect_precision_loss(true)
            .build();
        
        let verifier = EVMVerify::with_config(config);
        
        // Analyze the bytecode specifically for precision vulnerabilities
        let vulnerabilities = verifier
            .analyze_precision_vulnerabilities(Bytes::from(vulnerable_bytecode.clone()))
            .unwrap();
        
        // There should be at least one vulnerability
        assert!(!vulnerabilities.is_empty());
        
        // At least one vulnerability should be related to division before multiplication
        let has_div_before_mul = vulnerabilities.iter().any(|v| 
            v.description.contains("division before multiplication") || 
            v.description.contains("precision loss")
        );
        
        assert!(has_div_before_mul, "Expected to find division before multiplication vulnerability");
    }

    #[test]
    fn test_integration_precision_safe_contract() {
        // Simple bytecode with a safe multiplication before division
        // PUSH1 10 (amount)
        // PUSH1 20 (ratio)
        // MUL
        // PUSH1 100 (total)
        // DIV
        let safe_bytecode = vec![
            0x60, 0x0a, // PUSH1 10 (amount)
            0x60, 0x14, // PUSH1 20 (ratio)
            0x02,       // MUL
            0x60, 0x64, // PUSH1 100 (total)
            0x04,       // DIV
        ];
        
        // Create the circuit
        let circuit = create_test_circuit::<ark_bn254::Fr>(&safe_bytecode);
        
        // Test integration with the API
        let config = ConfigManager::builder()
            .detect_precision_loss(true)
            .build();
        
        let verifier = EVMVerify::with_config(config);
        
        // Analyze the bytecode specifically for precision vulnerabilities
        let vulnerabilities = verifier
            .analyze_precision_vulnerabilities(Bytes::from(safe_bytecode.clone()))
            .unwrap();
        
        // There should be no precision vulnerabilities
        assert!(
            vulnerabilities.iter().all(|v| !v.description.contains("division before multiplication")),
            "Expected no division before multiplication vulnerabilities"
        );
    }
}
