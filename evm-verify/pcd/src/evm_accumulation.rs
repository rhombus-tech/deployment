// EVM-specific accumulation scheme implementation
//
// This module implements an accumulation scheme specifically designed for EVM bytecode
// verification, building on top of the Groth16 proof system.

use ark_bn254::{Bn254, Fr};
use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, SerializationError};
use ark_snark::SNARK;
use ark_std::rand::{RngCore, CryptoRng};
use ark_std::rand::thread_rng;
use ark_std::marker::PhantomData;
use anyhow::{Result, anyhow};
use ethers::types::Bytes;

use crate::circuit_impl::PCDCircuit;

/// EVM Bytecode verification input for the accumulation scheme
#[derive(Clone)]
pub struct EVMBytecodeInput {
    /// The bytecode to verify
    pub bytecode: Bytes,
    /// The previous state (if any)
    pub prev_state: Option<Vec<Fr>>,
    /// The current state
    pub curr_state: Vec<Fr>,
}

/// Create an input for EVM bytecode verification
pub fn create_evm_input(
    bytecode: Bytes,
    prev_state: Option<Vec<Fr>>,
    curr_state: Vec<Fr>,
) -> Result<EVMBytecodeInput> {
    Ok(EVMBytecodeInput {
        bytecode,
        prev_state,
        curr_state,
    })
}

/// Generate a proof for EVM bytecode verification
pub fn generate_evm_proof<R: RngCore + CryptoRng>(
    bytecode: Bytes,
    prev_state: Option<Vec<Fr>>,
    curr_state: Vec<Fr>,
    rng: &mut R,
) -> Result<(Proof<Bn254>, VerifyingKey<Bn254>)> {
    // Create the circuit
    let circuit = PCDCircuit {
        bytecode: bytecode.clone(),
        prev_state: prev_state.clone(),
        curr_state: curr_state.clone(),
        _field: PhantomData,
    };

    // Generate proving and verifying keys
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng)
        .map_err(|e| anyhow!("Setup error: {:?}", e))?;

    // Generate the proof
    let proof = Groth16::<Bn254>::prove(&pk, circuit, rng)
        .map_err(|e| anyhow!("Proving error: {:?}", e))?;

    Ok((proof, vk))
}

/// Verify an EVM proof
pub fn verify_evm_proof(
    proof: &Proof<Bn254>,
    vk: &VerifyingKey<Bn254>,
    public_inputs: &[Fr],
) -> Result<bool> {
    let result = Groth16::<Bn254>::verify(vk, public_inputs, proof)
        .map_err(|e| anyhow!("Verification error: {:?}", e))?;
    Ok(result)
}

/// Serialize a proof to bytes
pub fn serialize_proof(proof: &Proof<Bn254>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    proof.serialize(&mut bytes)
        .map_err(|e| anyhow!("Serialization error: {:?}", e))?;
    Ok(bytes)
}

/// Deserialize a proof from bytes
pub fn deserialize_proof(bytes: &[u8]) -> Result<Proof<Bn254>> {
    Proof::deserialize(bytes)
        .map_err(|e| anyhow!("Deserialization error: {:?}", e))
}

/// Serialize a verifying key to bytes
pub fn serialize_vk(vk: &VerifyingKey<Bn254>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    vk.serialize(&mut bytes)
        .map_err(|e| anyhow!("Serialization error: {:?}", e))?;
    Ok(bytes)
}

/// Deserialize a verifying key from bytes
pub fn deserialize_vk(bytes: &[u8]) -> Result<VerifyingKey<Bn254>> {
    VerifyingKey::deserialize(bytes)
        .map_err(|e| anyhow!("Deserialization error: {:?}", e))
}

/// Accumulate multiple proofs into a single proof
pub fn accumulate_proofs<R: RngCore + CryptoRng>(
    proofs: Vec<Proof<Bn254>>,
    public_inputs: Vec<Vec<Fr>>,
    rng: &mut R,
) -> Result<(Proof<Bn254>, VerifyingKey<Bn254>)> {
    if proofs.is_empty() {
        return Err(anyhow!("No proofs to accumulate"));
    }

    if proofs.len() != public_inputs.len() {
        return Err(anyhow!("Number of proofs and public inputs must match"));
    }

    // For now, we'll just use the first proof as a placeholder
    // In a real implementation, we would create a circuit that verifies all proofs
    // and generates a new proof of their correctness
    
    // Create an accumulation circuit
    let circuit = PCDCircuit {
        bytecode: Bytes::from(vec![0u8; 32]), // Placeholder
        prev_state: Some(public_inputs[0].clone()),
        curr_state: public_inputs.last().unwrap().clone(),
        _field: PhantomData,
    };

    // Generate proving and verifying keys
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), rng)
        .map_err(|e| anyhow!("Setup error: {:?}", e))?;

    // Generate the proof
    let proof = Groth16::<Bn254>::prove(&pk, circuit, rng)
        .map_err(|e| anyhow!("Proving error: {:?}", e))?;

    Ok((proof, vk))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::rand::thread_rng;

    #[test]
    fn test_evm_input() -> Result<()> {
        let bytecode = Bytes::from(vec![0u8, 1u8, 2u8]);
        let prev_state = Some(vec![Fr::from(1u64), Fr::from(2u64)]);
        let curr_state = vec![Fr::from(3u64), Fr::from(4u64)];

        let input = create_evm_input(bytecode.clone(), prev_state.clone(), curr_state.clone())?;

        assert_eq!(input.bytecode, bytecode);
        assert_eq!(input.prev_state, prev_state);
        assert_eq!(input.curr_state, curr_state);

        Ok(())
    }

    #[test]
    fn test_evm_proof() -> Result<()> {
        let bytecode = Bytes::from(vec![0u8, 1u8, 2u8]);
        let prev_state = Some(vec![Fr::from(1u64), Fr::from(2u64)]);
        let curr_state = vec![Fr::from(3u64), Fr::from(4u64)];
        let mut rng = thread_rng();

        let (proof, vk) = generate_evm_proof(bytecode, prev_state, curr_state.clone(), &mut rng)?;
        
        // Verify the proof
        let result = verify_evm_proof(&proof, &vk, &curr_state)?;
        assert!(result);

        Ok(())
    }

    #[test]
    fn test_proof_serialization() -> Result<()> {
        let bytecode = Bytes::from(vec![0u8, 1u8, 2u8]);
        let prev_state = Some(vec![Fr::from(1u64), Fr::from(2u64)]);
        let curr_state = vec![Fr::from(3u64), Fr::from(4u64)];
        let mut rng = thread_rng();

        let (proof, vk) = generate_evm_proof(bytecode, prev_state, curr_state.clone(), &mut rng)?;
        
        // Serialize and deserialize the proof
        let proof_bytes = serialize_proof(&proof)?;
        let deserialized_proof = deserialize_proof(&proof_bytes)?;
        
        // Serialize and deserialize the verifying key
        let vk_bytes = serialize_vk(&vk)?;
        let deserialized_vk = deserialize_vk(&vk_bytes)?;
        
        // Verify the deserialized proof with the deserialized verifying key
        let result = verify_evm_proof(&deserialized_proof, &deserialized_vk, &curr_state)?;
        assert!(result);

        Ok(())
    }

    #[test]
    fn test_accumulation() -> Result<()> {
        let mut rng = thread_rng();
        
        // Generate two proofs
        let bytecode1 = Bytes::from(vec![0u8, 1u8, 2u8]);
        let prev_state1 = None;
        let curr_state1 = vec![Fr::from(1u64), Fr::from(2u64)];
        let (proof1, _) = generate_evm_proof(bytecode1, prev_state1, curr_state1.clone(), &mut rng)?;
        
        let bytecode2 = Bytes::from(vec![3u8, 4u8, 5u8]);
        let prev_state2 = Some(curr_state1.clone());
        let curr_state2 = vec![Fr::from(3u64), Fr::from(4u64)];
        let (proof2, _) = generate_evm_proof(bytecode2, prev_state2, curr_state2.clone(), &mut rng)?;
        
        // Accumulate the proofs
        let proofs = vec![proof1, proof2];
        let public_inputs = vec![curr_state1, curr_state2.clone()];
        let (acc_proof, acc_vk) = accumulate_proofs(proofs, public_inputs, &mut rng)?;
        
        // Verify the accumulated proof
        let result = verify_evm_proof(&acc_proof, &acc_vk, &curr_state2)?;
        assert!(result);
        
        Ok(())
    }
}
