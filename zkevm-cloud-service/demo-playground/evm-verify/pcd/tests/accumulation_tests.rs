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
                curr_state,
                &proof,
                &vk,
            )?;

            assert!(is_valid, "Proof should be valid");
            Ok(())
        }

        #[test]
        fn test_accumulation() -> Result<()> {
            // Create two simple bytecodes
            let bytecode1 = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]); // PUSH1 1 PUSH1 0 SSTORE
            let bytecode2 = Bytes::from(vec![0x60, 0x02, 0x60, 0x01, 0x55]); // PUSH1 2 PUSH1 1 SSTORE

            // Generate proofs
            let mut rng = thread_rng();
            let curr_state1 = vec![Fr::from(1u32)];
            let curr_state2 = vec![Fr::from(2u32)];

            let (proof1, vk1) = generate_evm_proof(
                bytecode1.clone(),
                None,
                curr_state1.clone(),
                &mut rng,
            )?;

            let (proof2, vk2) = generate_evm_proof(
                bytecode2.clone(),
                None,
                curr_state2.clone(),
                &mut rng,
            )?;

            // Accumulate the proofs
            let proofs = vec![proof1, proof2];
            let vks = vec![vk1, vk2];
            let public_inputs = vec![curr_state1, curr_state2];

            let (accumulated_proof, _accumulated_vk) = accumulate_proofs(
                proofs,
                vks,
                public_inputs,
                &mut rng,
            )?;
            
            // Verify that we got a valid proof
            assert!(!accumulated_proof.a.is_zero());
            
            Ok(())
        }

        #[test]
        fn test_multiple_accumulations() -> Result<()> {
            // Create three simple bytecodes
            let bytecode1 = Bytes::from(vec![0x60, 0x01, 0x60, 0x00, 0x55]); // PUSH1 1 PUSH1 0 SSTORE
            let bytecode2 = Bytes::from(vec![0x60, 0x02, 0x60, 0x01, 0x55]); // PUSH1 2 PUSH1 1 SSTORE
            let bytecode3 = Bytes::from(vec![0x60, 0x03, 0x60, 0x02, 0x55]); // PUSH1 3 PUSH1 2 SSTORE

            // Generate proofs
            let mut rng = thread_rng();
            let curr_state1 = vec![Fr::from(1u32)];
            let curr_state2 = vec![Fr::from(2u32)];
            let curr_state3 = vec![Fr::from(3u32)];

            let (proof1, vk1) = generate_evm_proof(
                bytecode1.clone(),
                None,
                curr_state1.clone(),
                &mut rng,
            )?;

            let (proof2, vk2) = generate_evm_proof(
                bytecode2.clone(),
                None,
                curr_state2.clone(),
                &mut rng,
            )?;

            let (proof3, vk3) = generate_evm_proof(
                bytecode3.clone(),
                None,
                curr_state3.clone(),
                &mut rng,
            )?;

            // Accumulate the proofs
            let proofs = vec![proof1, proof2, proof3];
            let vks = vec![vk1, vk2, vk3];
            let public_inputs = vec![curr_state1, curr_state2, curr_state3];

            let (accumulated_proof, _accumulated_vk) = accumulate_proofs(
                proofs,
                vks,
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

            // Serialize the proof
            let serialized_proof = serialize_proof(&proof)?;
            assert!(!serialized_proof.is_empty(), "Serialized proof should not be empty");

            // Deserialize the proof
            let deserialized_proof = deserialize_proof(&serialized_proof)?;

            // Verify the deserialized proof
            let is_valid = verify_evm_proof(
                bytecode,
                curr_state,
                &deserialized_proof,
                &vk,
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
                curr_state: vec![Fr::from(1u32)],
            };

            assert_eq!(input.bytecode, bytecode, "Bytecode should match");
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

            // Generate a proof for the initial state
            let mut rng = thread_rng();
            let initial_state = vec![Fr::from(1u32)];
            let (proof1, vk1) = generate_evm_proof(
                bytecode.clone(),
                None,
                initial_state.clone(),
                &mut rng,
            )?;

            // Generate a proof for the next state
            let next_state = vec![Fr::from(2u32)];
            let (proof2, vk2) = generate_evm_proof(
                bytecode.clone(),
                Some(initial_state.clone()),
                next_state.clone(),
                &mut rng,
            )?;

            // Verify both proofs
            let is_valid1 = verify_evm_proof(
                bytecode.clone(),
                initial_state.clone(),
                &proof1,
                &vk1,
            )?;

            let is_valid2 = verify_evm_proof(
                bytecode.clone(),
                next_state.clone(),
                &proof2,
                &vk2,
            )?;

            assert!(is_valid1, "First proof should be valid");
            assert!(is_valid2, "Second proof should be valid");

            // Accumulate the proofs
            let proofs = vec![proof1, proof2];
            let vks = vec![vk1, vk2];
            let public_inputs = vec![initial_state, next_state];

            let (accumulated_proof, _accumulated_vk) = accumulate_proofs(
                proofs,
                vks,
                public_inputs,
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

            // Generate a proof and measure the time
            let mut rng = thread_rng();
            let curr_state = vec![Fr::from(1u32)];

            let start = Instant::now();
            let (proof, vk) = generate_evm_proof(
                bytecode.clone(),
                None,
                curr_state.clone(),
                &mut rng,
            )?;
            let proof_generation_time = start.elapsed();

            println!("Proof generation time: {:?}", proof_generation_time);

            // Verify the proof and measure the time
            let start = Instant::now();
            let is_valid = verify_evm_proof(
                bytecode.clone(),
                curr_state.clone(),
                &proof,
                &vk,
            )?;
            let proof_verification_time = start.elapsed();

            println!("Proof verification time: {:?}", proof_verification_time);
            assert!(is_valid, "Proof should be valid");

            // Accumulate proofs and measure the time
            let proofs = vec![proof.clone(), proof];
            let vks = vec![vk.clone(), vk];
            let public_inputs = vec![curr_state.clone(), curr_state];

            let start = Instant::now();
            let (accumulated_proof, _accumulated_vk) = accumulate_proofs(
                proofs,
                vks,
                public_inputs,
                &mut rng,
            )?;
            let accumulation_time = start.elapsed();

            println!("Proof accumulation time: {:?}", accumulation_time);
            assert!(!accumulated_proof.a.is_zero());

            Ok(())
        }
    }
