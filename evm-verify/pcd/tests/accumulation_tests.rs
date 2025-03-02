#[cfg(feature = "accumulation")]
    mod accumulation_tests {
        use anyhow::Result;
        use ark_bn254::Fr;
        use ark_ff::Zero;
        use ark_std::rand::thread_rng;
        use ethers::types::Bytes;
        use pcd::evm_accumulation::{
            generate_evm_proof, verify_evm_proof, EVMBytecodeInput,
            accumulate_proofs, deserialize_proof, serialize_proof,
        };
        use std::time::Instant;

        #[test]
        fn test_proof_generation_and_verification() -> Result<()> {
            // Create a simple bytecode
            let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]); // PUSH1 1 PUSH1 0 SSTORE

            // Generate a proof
            let mut rng = thread_rng();
            let curr_state = vec![Fr::from(1u32)];
            let (proof, vk) = generate_evm_proof(
                bytecode.clone(),
                None,
                curr_state.clone(),
                &mut rng,
            )?;

            // Verify the proof
            let is_valid = verify_evm_proof(
                bytecode,
                &proof,
                &vk,
                curr_state,
            )?;

            assert!(is_valid, "Proof verification should succeed");

            Ok(())
        }

        #[test]
        fn test_accumulation() -> Result<()> {
            // Create two simple bytecodes
            let bytecode1 = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]);
            let bytecode2 = Bytes::from(vec![0x60, 0x02, 0x60, 0x01, 0x55]);
            
            // Generate proofs for both bytecodes
            let mut rng = thread_rng();
            let curr_state1 = vec![Fr::from(1u32)];
            let (proof1, _vk1) = generate_evm_proof(
                bytecode1,
                None,
                curr_state1.clone(),
                &mut rng,
            )?;
            
            let curr_state2 = vec![Fr::from(2u32)];
            let (proof2, _vk2) = generate_evm_proof(
                bytecode2,
                Some(vec![Fr::from(1u32)]),
                curr_state2.clone(),
                &mut rng,
            )?;
            
            // Accumulate the proofs
            let proofs = vec![proof1, proof2];
            let public_inputs = vec![curr_state1, curr_state2];
            
            let (accumulated_proof, _accumulated_vk) = accumulate_proofs(
                proofs,
                public_inputs,
                &mut rng,
            )?;
            
            // Verify that we got a valid proof
            assert!(!accumulated_proof.a.is_zero());
            
            Ok(())
        }

        #[test]
        fn test_multiple_accumulations() -> Result<()> {
            // Create multiple bytecodes
            let bytecodes = (0..5).map(|i| {
                Bytes::from(vec![0x60, i as u8, 0x60, 0x00, 0x55])
            }).collect::<Vec<_>>();
            
            // Generate proofs for all bytecodes
            let mut rng = thread_rng();
            let mut proofs = Vec::new();
            let mut public_inputs = Vec::new();
            
            for (i, bytecode) in bytecodes.iter().enumerate() {
                let prev_state = if i == 0 { None } else { Some(vec![Fr::from(i as u32)]) };
                let curr_state = vec![Fr::from((i + 1) as u32)];
                
                let (proof, _) = generate_evm_proof(
                    bytecode.clone(),
                    prev_state.clone(),
                    curr_state.clone(),
                    &mut rng,
                )?;
                
                proofs.push(proof);
                public_inputs.push(curr_state);
            }
            
            // Accumulate all proofs
            let (accumulated_proof, _accumulated_vk) = accumulate_proofs(
                proofs,
                public_inputs,
                &mut rng,
            )?;
            
            // Verify that we got a valid proof
            assert!(!accumulated_proof.a.is_zero());
            
            Ok(())
        }

        #[test]
        fn test_serialization() -> Result<()> {
            // Create a simple bytecode
            let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]);
            
            // Generate a proof
            let mut rng = thread_rng();
            let curr_state = vec![Fr::from(1u32)];
            let (proof, vk) = generate_evm_proof(
                bytecode.clone(),
                None,
                curr_state.clone(),
                &mut rng,
            )?;
            
            // Serialize the proof
            let proof_bytes = serialize_proof(&proof)?;
            
            // Deserialize the proof
            let deserialized_proof = deserialize_proof(&proof_bytes)?;
            
            // Verify the deserialized proof
            let is_valid = verify_evm_proof(
                bytecode,
                &deserialized_proof,
                &vk,
                curr_state,
            )?;
            
            assert!(is_valid, "Deserialized proof should be valid");
            
            Ok(())
        }

        #[test]
        fn test_create_evm_input() -> Result<()> {
            // Create a simple bytecode
            let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]); // PUSH1 1 PUSH1 0 SSTORE

            // Create an input for the accumulation scheme
            let input = EVMBytecodeInput {
                bytecode: bytecode.clone(),
                prev_state: None,
                curr_state: vec![Fr::from(1u32)],
            };

            assert_eq!(input.bytecode, bytecode, "Bytecode should match");
            assert_eq!(input.prev_state, None, "Previous state should be None");
            assert_eq!(
                input.curr_state,
                vec![Fr::from(1u32)],
                "Current state should match"
            );

            Ok(())
        }

        #[test]
        fn test_state_transition() -> Result<()> {
            // Create a simple bytecode
            let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]); // PUSH1 1 PUSH1 0 SSTORE

            // Track the current state
            let mut current_state = vec![Fr::from(0u32)];

            // Generate proofs for 5 state transitions
            let mut rng = thread_rng();
            let mut proofs = Vec::new();
            let mut states = Vec::new();

            // Generate proofs for 5 state transitions
            for i in 1..6 {
                let input = EVMBytecodeInput {
                    bytecode: bytecode.clone(),
                    prev_state: Some(current_state.clone()),
                    curr_state: vec![Fr::from(i as u32)],
                };

                let (proof, _) = generate_evm_proof(
                    input.bytecode.clone(),
                    input.prev_state.clone(),
                    input.curr_state.clone(),
                    &mut rng,
                )?;

                current_state = input.curr_state.clone();
                proofs.push(proof);
                states.push(current_state.clone());
            }

            // Accumulate all proofs
            let (accumulated_proof, _accumulated_vk) = accumulate_proofs(
                proofs,
                states,
                &mut rng,
            )?;
            
            // Verify that we got a valid proof
            assert!(!accumulated_proof.a.is_zero());
            
            Ok(())
        }

        #[test]
        fn test_performance() -> Result<()> {
            // Create a simple bytecode
            let bytecode = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]); // PUSH1 1 PUSH1 0 SSTORE

            // Generate 10 proofs
            let mut rng = thread_rng();
            let mut proofs = Vec::new();
            let mut inputs = Vec::new();

            let start = Instant::now();
            for i in 0..10 {
                let input = EVMBytecodeInput {
                    bytecode: bytecode.clone(),
                    prev_state: None,
                    curr_state: vec![Fr::from(i as u32)],
                };
                let (proof, _) = generate_evm_proof(
                    input.bytecode.clone(),
                    input.prev_state.clone(),
                    input.curr_state.clone(),
                    &mut rng,
                )?;
                proofs.push(proof);
                inputs.push(input);
            }
            let generation_time = start.elapsed();
            println!("Time to generate 10 proofs: {:?}", generation_time);

            // Accumulate and verify
            let start = Instant::now();
            let (accumulated_proof, _accumulated_vk) = accumulate_proofs(
                proofs,
                inputs.iter().map(|input| input.curr_state.clone()).collect(),
                &mut rng,
            )?;
            
            // Verify that we got a valid proof
            assert!(!accumulated_proof.a.is_zero());
            
            let accumulated_verification_time = start.elapsed();
            println!(
                "Time to accumulate and verify 10 proofs: {:?}",
                accumulated_verification_time
            );

            Ok(())
        }
    }
